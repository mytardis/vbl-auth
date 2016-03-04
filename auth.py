# -*- coding: utf-8 -*-
#
# Copyright (c) 2010-2011, Monash e-Research Centre
#   (Monash University, Australia)
# Copyright (c) 2010-2011, VeRSI Consortium
#   (Victorian eResearch Strategic Initiative, Australia)
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    *  Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    *  Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#    *  Neither the name of the VeRSI, the VeRSI Consortium members, nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
'''
Created on 10/12/2010

.. moduleauthor:: Ulrich Felzmann <ulrich.felzmann@versi.edu.au>
.. moduleauthor:: Gerson Galang <gerson.galang@versi.edu.au>
'''

import logging
from string import lower
from suds.client import Client
import json

from django.conf import settings

from tardis.tardis_portal.auth.interfaces import GroupProvider, AuthProvider, \
    UserProvider
from tardis.tardis_portal.models import (
    UserAuthentication, ExperimentParameterSet, ObjectACL)


logger = logging.getLogger('tardis.vbl')


EPN_LIST = "_epn_list"

auth_key = u'vbl'
auth_display_name = u'VBL'


class VblMiddleware(object):
    def process_request(self, request):
        if EPN_LIST in request.session:
            request.user.epn_list = request.session[EPN_LIST]
        return None


class VblGroupProvider(GroupProvider):
    name = u'vbl_group'

    def __init__(self):
        try:
            self.VBLTARDISINTERFACE = settings.VBLTARDISINTERFACE
        except AttributeError:
            logger.exception('setting VBLTARDISINTERFACE not configured')
            self.VBLTARDISINTERFACE = None
            return

        self.client = Client(self.VBLTARDISINTERFACE, cache=None)

    def getGroups(self, user):
        """
        Return an iteration of the available EPNs for a user from the
        VBL. This determines which experiments a authenticated user is
        allowed to see. The VBL SOAP webservice returns a string with
        EPNs, separated by commas (',') which is also stored in the
        session variable.

        """

        # the user needs to be authenticated
        if not user.is_authenticated():
            return []

        # check if the user is linked to any experiments
        if not hasattr(user, 'epn_list'):
            # apparently this user did not login using the
            # vbl authentication backend
            if not self.VBLTARDISINTERFACE:
                return []

            # check if a vbl profile exists
            try:
                userAuth = UserAuthentication.objects.get(
                    userProfile__user=user,
                    authenticationMethod=auth_key)

            except UserAuthentication.DoesNotExist:
                return []

            # ok, we got the vbl username, query the vbl now
            result = str(
                self.client.service.VBLgetExpIDsFromEmail(userAuth.username))
            return result.split(',')

        # the epns should be stored in the session if the user
        # authenticated against the vbl backend below
        epnList = user.epn_list
        return epnList

    def getGroupById(self, id):
        """
        return the group associated with the id::

            {"id": 123,
            "display": "Group Name",}

        """
        return {'id': id,
                'display': 'EPN_%i' % id}

    def searchGroups(self, **filter):
        if not self.VBLTARDISINTERFACE:
            return []

        epn = filter.get('name')
        if not epn:
            return []

        users = str(self.client.service.VBLgetEmailsFromExpID(epn))
        if not users == 'None':

            # chop off literals (a,b,c) from epn (2467a -> 2467)
            from re import match
            epn = match('\d*', epn).group(0)

            return [{'id': int(epn),
                     'display': 'VBL/EPN_%s' % epn,
                     'members': users.split(',')}]
        else:
            return []

    def getGroupsForEntity(self, entity):
        """
        return a list of the EPNs for a particular user

           [{'name': 'Group 456', 'id': '2'},
           {'name': 'Group 123', 'id': '1'}]

        """
        result = str(self.client.service.VBLgetExpIDsFromEmail(entity))
        if not result == 'None':
            return [{'id': epn,
                     'name': 'EPN_%i' % epn} for epn in result.split(',')]
        else:
            return []


class Backend(AuthProvider, UserProvider):
    """
    Authenticate against the VBL SOAP Webservice. It is assumed that the
    request object contains the username and password to be provided to the
    VBLgetExpIDs function.

    a new local user is created if it doesn't already exist

    """

    def authenticate(self, request):
        username = lower(request.POST['username'])
        password = request.POST['password']

        if not username or not password:
            return None

        # authenticate user and update group memberships
        try:
            VBLTARDISINTERFACE = settings.VBLTARDISINTERFACE
        except AttributeError:
            logger.error('setting VBLTARDISINTERFACE not configured')
            return None

        try:
            # Switch the suds cache off, otherwise suds will try to
            # create a tmp directory in /tmp. If it already exists but
            # has the wrong permissions, the authentication will fail.
            client = Client(VBLTARDISINTERFACE, cache=None)
        except:
            logger.exception()
            return None

        result = str(client.service.VBLauthenticate(username, password))
        try:
            user_info = json.loads(result)
        except:
            user_info = None

        if not user_info:
            logger.error('VBLauthenticate: %s %s' % (username, result))
            return None

        # result contains comma separated list of epns the user is
        # allowed to see
        request.session[EPN_LIST] = user_info['epns']
        request.user.epn_list = user_info['epns']
        logger.info('%s %s %s' % (user_info['name'], user_info['username'],
                                  user_info['epns']))
        logger.info(user_info)

        # need to make sure ObjectACLs exist for all epns
        for epn in user_info['epns']:
            try:
                # create vbl group
                exp = ExperimentParameterSet.objects.get(
                    experimentparameter__string_value=epn,
                    experimentparameter__name__name='EPN').experiment
                acls = ObjectACL.objects.filter(
                    content_type=exp.get_ct(),
                    object_id=exp.id,
                    pluginId='vbl_group',
                    entityId=epn,
                    canRead=True,
                    aclOwnershipType=ObjectACL.SYSTEM_OWNED)
                if len(acls) == 0:
                    acl = ObjectACL(content_type=exp.get_ct(),
                                    object_id=exp.id,
                                    pluginId='vbl_group',
                                    entityId=epn,
                                    canRead=True,
                                    aclOwnershipType=ObjectACL.SYSTEM_OWNED)
                    acl.save()

                from django.contrib.auth.models import Group
                from tardis.tardis_portal.auth.localdb_auth import django_group

                beamline_group = "BEAMLINE_MX"
                group, created = Group.objects.get_or_create(name=beamline_group)

                acl = ObjectACL(content_type=exp.get_ct(),
                                object_id=exp.id,
                                pluginId=django_group,
                                entityId=str(group.id),
                                canRead=True,
                                aclOwnershipType=ObjectACL.SYSTEM_OWNED)
                acl.save()

                group, created = Group.objects.get_or_create(name='admin')
                acl = ObjectACL(content_type=exp.get_ct(),
                                object_id=exp.id,
                                pluginId=django_group,
                                entityId=str(group.id),
                                isOwner=True,
                                canRead=True,
                                aclOwnershipType=ObjectACL.SYSTEM_OWNED)
                acl.save()

            except ExperimentParameterSet.DoesNotExist:
                pass

        return self._make_user_dict(user_info)

    def get_user(self, user_id):
        if user_id is None:
            return None

        try:
            VBLTARDISINTERFACE = settings.VBLTARDISINTERFACE
        except AttributeError:
            logger.error('setting VBLTARDISINTERFACE not configured')
            return None

        try:
            # Switch the suds cache off, otherwise suds will try to
            # create a tmp directory in /tmp. If it already exists but
            # has the wrong permissions, the authentication will fail.
            client = Client(VBLTARDISINTERFACE, cache=None)
        except:
            logger.exception('Error connecting to VBL via SOAP')
            return None

        result = str(client.service.VBLgetUserInfo(user_id))
        try:
            user_info = json.loads(result)
        except:
            user_info = None

        if not user_info:
            logger.error('VBLgetUserInfo: %s %s' % (user_id, result))
            return None
        else:
            logger.info('get_user: %s %s' % (user_id, user_info))

        return self._make_user_dict(user_info)

    def getUserInfo(self, user_id):
        return self.get_user(user_id)

    # UserProvider
    def getUsernameByEmail(self, email):
        return email

    def _make_user_dict(self, user_info):
        # the authentication provider convention, however the vbl
        # does not distinguish between usernames and emails
        return {
            'display': user_info['name'],
            'id': user_info['username'],
            'email': user_info['username'],
            'first_name': user_info['first_name'],
            'last_name': user_info['last_name'],
        }
