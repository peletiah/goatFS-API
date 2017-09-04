import uuid as uuidlib
from datetime import datetime, timedelta
import json
import logging


from sqlalchemy import (
    Column,
    Index,
    Integer,
    Text,
    Table,
    types,
    ForeignKey,
    UniqueConstraint,
    Unicode,
)

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.dialects import postgresql

from sqlalchemy.orm import (
    scoped_session,
    sessionmaker,
    relationship,
    backref,
    exc as orm_exc
    )

from pyramid.security import (
    Allow,
    Deny,
    Everyone,
    Authenticated,
    authenticated_userid,
    forget,
    remember,
    ALL_PERMISSIONS
    )

from zope.sqlalchemy import ZopeTransactionExtension
from passlib.hash import bcrypt

import ziggurat_foundations.models
from ziggurat_foundations.models.base import BaseModel, get_db_session
from ziggurat_foundations.models.services.resource import ResourceService
from ziggurat_foundations.models.external_identity import ExternalIdentityMixin
from ziggurat_foundations.models.group import GroupMixin
from ziggurat_foundations.models.group_permission import GroupPermissionMixin
from ziggurat_foundations.models.group_resource_permission import GroupResourcePermissionMixin
from ziggurat_foundations.models.resource import ResourceMixin
from ziggurat_foundations.models.user import UserMixin
from ziggurat_foundations.models.user_group import UserGroupMixin
from ziggurat_foundations.models.user_permission import UserPermissionMixin
from ziggurat_foundations.models.user_resource_permission import UserResourcePermissionMixin
from ziggurat_foundations import ziggurat_model_init


from goatfs_api.lib import timetools
from .meta import Base


log = logging.getLogger(__name__)



#################
# n-n-Link tables
#################

user_directory_key_value_store_table = Table('user_directory_key_value_store', Base.metadata,
    Column('user_directory_id', Integer, ForeignKey('user_directory.id', onupdate="CASCADE", ondelete="CASCADE"), primary_key=True),
    Column('key_value_store_id', Integer, ForeignKey('key_value_store.id',onupdate="CASCADE", ondelete="CASCADE"), primary_key=True),
    UniqueConstraint('user_directory_id', 'key_value_store_id', name='user_directory_key_value_store_id'))

extension_group_table = Table('extensions_groups', Base.metadata,
    Column('extension_id', Integer, ForeignKey('extension.id', onupdate="CASCADE", ondelete="CASCADE"), primary_key=True),
    Column('group_id', Integer, ForeignKey('groups.id',onupdate="CASCADE", ondelete="CASCADE"), primary_key=True),
    UniqueConstraint('extension_id', 'group_id', name='extension_id_group_id'))


######################################
# ZIGGURAT FOUNDATION CLASS DEFINITION
######################################


class GroupPermission(GroupPermissionMixin, Base):
    pass

class UserGroup(UserGroupMixin, Base):
    pass

class GroupResourcePermission(GroupResourcePermissionMixin, Base):
    pass

class Resource(ResourceMixin, Base):
    def by_resource_name(name,db_session=None):
        db_session = get_db_session(db_session)
        try:
            resource = db_session.query(Resource).filter(Resource.resource_name==name).one()
            log.debug(resource)
            return ResourceService.by_resource_id(resource_id=resource.resource_id,
                                                  db_session=db_session)
        except Exception as e:
            log.debug('Error retrieving resource by name, {0}'.format(e))
            raise

class UserPermission(UserPermissionMixin, Base):
    pass

class UserResourcePermission(UserResourcePermissionMixin, Base):
    pass

class ExternalIdentity(ExternalIdentityMixin, Base):
    pass

class Domain(Base):
    __tablename__ = 'domain'
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(Text, unique=True)

    def __str__(self):
        return str(self.__dict__)

    def __init__(self,domain):
        self.domain = domain


class User(UserMixin, Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    user_name = Column(types.UnicodeText, unique=True)
    user_password = Column(types.UnicodeText)
    email = Column(types.UnicodeText)
    status = Column(postgresql.SMALLINT, nullable=False, default=1)
    security_code = Column(types.UnicodeText)
    last_login_date = Column(types.TIMESTAMP(timezone=False), default=timetools.now())
    registered_date = Column(types.TIMESTAMP(timezone=False), default=timetools.now())
    security_code_date = Column(types.TIMESTAMP(timezone=False), default=timetools.now())


    @classmethod
    def get_user(self, login, request):
        try:
            query = request.dbsession.query(User)
            user = query.filter(User.user_name == login).one()
            return user
        except Exception as e:
            log.debug('Error retrieving user: "{0}" - {1}'.format(login,e))
            return None

    @classmethod
    def get_users(self):
        users = DBSession.query(User).all()
        return users

    def verify_password(cls, password, request):
        #cls is used instead of self, see PEP-8
        log.debug('verify_password with {0}, {1}'.format(password,cls.user_password))
        try:
            if bcrypt.verify(password,cls.user_password):
                return True
            else:
                return False
        except Exception as e:
            log.debug('Error verifying password: {0}'.format(e))
            return False


class Group(GroupMixin, Base):
    __tablename__ = 'groups'
    id = Column(Integer, primary_key=True)
    group_name = Column(types.UnicodeText, unique=True)
    description = Column(types.UnicodeText)
    member_count = Column(Integer)
    extensions = relationship('Extension', secondary=extension_group_table, backref='members')

    @property
    def __acl__(self):
        # this acl is only appended when a traverse-route is used
        # only allow members of this group to add new members
        access_list = [(Allow, 'g:{0}'.format(self.name), 'edit')]
        log.debug('GROUP access list: {0}'.format(access_list))
        return access_list

    def __init__(self, name):
        self.name = name

    @classmethod
    def get_group(self, name, request):
        log.debug(name)
        group = request.dbsession.query(Group).filter(Group.name == name).one()
        return group

    def get_group_by_id(request, id):
        try:
            group = request.dbsession.query(Group).filter(Group.id == id).one()
            return group
        except Exception as e:
            log.debug('Error retrieving group by id, {0}'.format(e))
            raise



class AuthToken(Base):
    __tablename__ = 'auth_token'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', onupdate="CASCADE", \
                        ondelete="CASCADE"))
    jwt_id = Column(postgresql.UUID, unique=True)
    created = Column(types.TIMESTAMP(timezone=False), default=timetools.now())
    expires = Column(types.TIMESTAMP(timezone=False), default=timetools.now())
    active = Column(types.Boolean, default=True, nullable=False)
    client_ip = Column(types.UnicodeText)
    user_agent = Column(types.UnicodeText)

    def __init__(self,
                 user_id, \
                 client_ip, \
                 user_agent,
                 expire_days, \
                 jwt_id=str(uuidlib.uuid4()), \
                 created=timetools.now(), \
                 active=True):
        self.user_id = user_id
        self.jwt_id = jwt_id
        self.created = created
        self.expires = created+timedelta(days=expire_days)
        self.active = active
        self.client_ip = client_ip
        self.user_agent = user_agent



class Menu(Base):
    __tablename__ = 'menu'
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domain.id', onupdate="CASCADE", \
                        ondelete="CASCADE"),unique=True)
    menu_items = relationship('MenuItem', order_by='asc(MenuItem.position)')


    def __init__(self, domain):
        self.domain_id = domain.id


    @classmethod
    def get_menu(self, domain_id, request):
        menu = request.dbsession.query(Menu).filter(Menu.domain_id == domain_id).one()
        return menu

    def reprJSON(self):
        for item in self.menu_items:
            log.debug(item.location)
        menu_items = [item.reprJSON() for item in self.menu_items]
        return menu_items


class MenuItem(Base):
    __tablename__ = 'menu_item'
    id = Column(Integer, primary_key=True)
    menu_id = Column(Integer, ForeignKey('menu.id', onupdate="CASCADE", \
                                                        ondelete="CASCADE"))
    position = Column(Integer)
    name = Column(types.UnicodeText, unique=True)
    location = Column(types.UnicodeText, unique=True)
    __table_args__ = (
                UniqueConstraint('menu_id', 'position', name='menu_id_position_key'),
                {}
                )


    def reprJSON(self):
        return dict(id=self.id, menu_id=self.menu_id, position=self.position,
                name=self.name, location=self.location)


class KeyValueStore(Base):

    __tablename__ = 'key_value_store'
    id = Column(Integer, primary_key=True)
    key = Column(types.UnicodeText)
    value = Column(types.UnicodeText)
    type = Column(types.UnicodeText)
    #user_directory = relationship('UserDirectory', secondary='user_directory_key_value_store_table')

    def __init__(self, key, value, type):
        self.key = key
        self.value = value
        self.type = type
     

class Extension(Base):

    __tablename__ = 'extension'
    id = Column(Integer, primary_key=True)
    extension = Column(types.UnicodeText)
    routes = relationship('Route', cascade='all, delete-orphan')
    action_bridge_user = relationship('ActionBridgeUser', uselist=False, back_populates='extension', cascade='all, delete-orphan')
    user_directory = relationship('UserDirectory', uselist=False, back_populates='extension', cascade='all, delete-orphan')
    groups = relationship('Group', secondary=extension_group_table, backref='memberships')

    def __init__(self, extension, domain_id):
        self.extension = extension
        self.domain_id = domain_id

    def get_by_id(request, extension_id):
        try:
            extension = request.dbsession.query(Extension).filter(Extension.id == extension_id).one()
            return extension
        except Exception as e:
            log.debug('Extension.get_by_id failed with {0}'.format(e))
            raise


    def reprJSON(self):
        extension = dict()
        extension['extension_id'] = self.id
        extension['extension'] = self.extension
        try:
            for kv in self.user_directory.settings:
                log.debug(kv.key)
                if kv.key == 'effective_caller_id_name':
                    extension['target'] = '{0} - {1}'.format(kv.value, self.extension)
            extension['type'] = 'user'
        except AttributeError:
            extension['target'] = '{0}'.format(self.extension)
            extension['type'] = 'extension'
        return extension



class UserDirectory(Base):
    __tablename__ = 'user_directory'
    id = Column(Integer, primary_key=True)
    extension_id = Column(Integer, ForeignKey('extension.id', onupdate='CASCADE', \
                            ondelete='CASCADE'))
    extension = relationship('Extension')
    settings = relationship('KeyValueStore', secondary=user_directory_key_value_store_table, backref='user_directory')


    def __init__(self, extension_id):
        self.extension_id = extension_id


class Route(Resource):
    __tablename__ = 'route'
    __mapper_args__ = {'polymorphic_identity': 'route'}
    id = Column(Integer, primary_key=True)
    resource_id = Column(Integer, ForeignKey('resources.resource_id', onupdate='CASCADE', \
                                                     ondelete='CASCADE')) 
    extension_id = Column(Integer, ForeignKey('extension.id', onupdate='CASCADE', \
                                                              ondelete='CASCADE'))
    sequences = relationship('Sequence', order_by='asc(Sequence.sequence)', cascade='all, delete-orphan')

    
    def reprJSON(self):
        route = {"id":self.id, "sequences" : [sequence.reprJSON() for sequence in self.sequences if sequence.reprJSON()]}
        return route

    def createJSON(self, sequences):
        route = {"id":self.id, "sequences" : sequences}
        return route

    def get_routes(request):
        try:
            routes = request.dbsession.query(Route).all()
            return routes
        except Exception as e:
            log.debug('Error retrieving routes, {0}'.format(e))
            raise

    def get_route_by_id(request, id):
        try:
            route = request.dbsession.query(Route).filter(Route.id==id).one()
            return route
        except Exception as e:
            log.debug('Error retrieving route by id, {0}'.format(e))
            raise

    def __acl__(self):
        return [
                (Allow, self.owner, 'edit')
        ]

class Sequence(Base):
    __tablename__ = 'sequence'
    id = Column(Integer, primary_key=True)
    route_id = Column(Integer, ForeignKey('route.id', onupdate='CASCADE', \
                                                      ondelete='CASCADE'))
    sequence = Column(Integer)
    timeout = Column(Integer, default=20)
    action = relationship('Action', uselist=False, back_populates='sequence', cascade='all, delete-orphan')
    __table_args__ = (
            UniqueConstraint('route_id', 'sequence', name='route_id_sequence_key'),
            {}
            )

    def __init__(self, route_id, sequence, timeout):
        self.route_id = route_id
        self.sequence = sequence
        self.timeout = timeout

    def get_by_id(request, sequence_id):
        try:
            sequence = request.dbsession.query(Sequence).filter(Sequence.id==sequence_id).one()
            return sequence 
        except orm_exc.NoResultFound:
            log.info('Sequence.get_by_id couldn\' find record for sequence_id {0}'.format(sequence_id))
            return None
        except Exception as e:
            log.debug('Error retrieving sequence by id for sequence_id {0}, {1}'.format(sequence_id, e))
            raise

    def reprJSON(self):
        try:
            return dict(self.action.reprJSON(), sequence_id=self.id, sequence=self.sequence, timeout=self.timeout) 
        except AttributeError:
            return dict()

    def createJSON(self, action):
        try:
            return dict(action.reprJSON(), sequence_id=self.id, sequence=self.sequence, timeout=self.timeout) 
        except AttributeError:
            return dict()



    def add_sequence_from_json(request, route, sequence_json):
        if 'timeout' not in sequence_json:
            timeout = None
        else:
            timeout = sequence_json['timeout']
        sequence_id = sequence_json['sequence_id']
        sequence = Sequence(route.id, sequence_json['sequence'], timeout)
        request.dbsession.add(sequence)
        request.dbsession.flush()
        return sequence

    def delete_by_id(request, sequence_id):
        try:
            sequence = Sequence.get_by_id(request, sequence_id)
            if sequence:
                request.dbsession.delete(sequence)
                request.dbsession.flush()
                return True
            else:
                log.info('Error deleting sequence_id {0}, this sequence does not appear to exist'.format(sequence_id))
                return False
        except Exception as e:
            log.debug('Error retrieving sequence by id for sequence_id {0}, {1}'.format(sequence_id, e))
            raise



        
class Action(Base):
    __tablename__ = 'action'
    id = Column(Integer, primary_key=True)
    sequence_id = Column(Integer, 
                            ForeignKey('sequence.id', onupdate='CASCADE', \
                                                      ondelete='CASCADE'),
                            unique=True)
    application_id = Column(Integer, ForeignKey('application_catalog.id', onupdate='CASCADE', \
                                                                  ondelete='CASCADE'))
    active = Column(types.Boolean, default=True)
    action_application = relationship('ActionApplication', uselist=False, back_populates='action', cascade='all, delete-orphan')
    action_bridge_user = relationship('ActionBridgeUser', cascade='all, delete-orphan')
    action_bridge_endpoint = relationship('ActionBridgeEndpoint', cascade='all, delete-orphan')
    application_catalog = relationship('ApplicationCatalog')
    sequence = relationship('Sequence')

    def __init__(self, sequence_id, application_id, active):
        self.sequence_id = sequence_id
        self.application_id = application_id
        self.active = active


    def reprJSON(self):
        if self.active == True:
            command = self.application_catalog.reprJSON()
            try:
                cmdData = self.action_application.application_data
            except AttributeError:
                # this is not an application-action
                self.application_catalog.reprJSON()
                cmdData = list()
                try:
                    for target in self.action_bridge_user:
                        target.reprJSON(cmdData)
                except AttributeError:
                    pass
                try:
                    for target in self.action_bridge_endpoint:
                        target.reprJSON(cmdData)
                except AttributeError:
                    pass

            return dict(cmdData=cmdData, command=command)

    def get_by_id(request, action_id):
        try:
            action = request.dbsession.query(Action).filter(Action.id==action_id).one()
            return sequence 
        except orm_exc.NoResultFound:
            log.info('Action.get_by_id couldn\' find record for action_id {0}'.format(action_id))
            return None
        except Exception as e:
            log.debug('Error retrieving action by id for action_id {0}, {1}'.format(action_id, e))
            raise

    def add_action_from_json(request, sequence, sequence_json):
        command = sequence_json['command']
        cmdData = sequence_json['cmdData']
        application_catalog_id = command['application_catalog_id']
        if application_catalog_id == -1:
            application = ApplicationCatalog.get_by_command( \
                request, command['command'])
        else:
            application = ApplicationCatalog.get_by_id( \
                request, application_catalog_id)

        action = Action(sequence.id, application.id, True)
        request.dbsession.add(action)
        request.dbsession.flush()

        if command['command'] == 'bridge':
            for target in cmdData:
                Action.add_bridge_targets(request, action, target)
        else:
            action_application = ActionApplication(action.id, cmdData)
            request.dbsession.add(action_application)
            request.dbsession.flush()
        return action

    def add_bridge_targets(request, action, target):
        if target['type'] in ['user','extension']:
            log.debug('Extension {0}'.format(target['extension_id']))
            extension = Extension.get_by_id(request, target['extension_id'])
            if extension != None:
                actionbridge = ActionBridgeUser( target['extension_id'], action.id )
                request.dbsession.add(actionbridge)
                request.dbsession.flush()
            #TODO Distinguish between User and Extension
        elif target['type'] == 'endpoint':
            actionbridge = ActionBridgeEndpoint(action.id, target['target'])
            request.dbsession.add(actionbridge)
            request.dbsession.flush()

    def delete_by_id(request, action_id):
        try:
            action = Action.get_by_id(request, action_id)
            if action:
                request.dbsession.delete(action)
                request.dbsession.flush()
                return True
            else:
                log.info('Error deleting action_id {0}, this action does not appear to exist, {1}'.format(action_id))
                return False
        except Exception as e:
            log.debug('Error retrieving action by id for action_id {0}, {1}'.format(action_id, e))
            raise




class ActionApplication(Base):
    __tablename__ = 'action_application'
    id = Column(Integer, primary_key=True)
    action_id = Column(Integer, ForeignKey('action.id', onupdate='CASCADE', \
                                                            ondelete='CASCADE'))
    application_data = Column(types.UnicodeText)
    action = relationship('Action')

    def __init__(self, action_id, application_data):
        self.action_id = action_id
        self.application_data = application_data


class ActionBridgeUser(Base):
    __tablename__ = 'action_bridge_user'
    id = Column(Integer, primary_key=True)
    action_id = Column(Integer, ForeignKey('action.id', onupdate='CASCADE', \
                                                            ondelete='CASCADE'))
    extension_id = Column(Integer, ForeignKey('extension.id', onupdate='CASCADE', \
                                                            ondelete='CASCADE'))
    action = relationship('Action')
    extension = relationship('Extension')

    def __init__(self, extension_id, action_id):
        self.extension_id = extension_id
        self.action_id = action_id

    def reprJSON(self, cmdData=list()):
        cmdData.append(self.extension.reprJSON())
        log.debug(self.extension.user_directory)
        return cmdData 

class ActionBridgeEndpoint(Base):
    __tablename__ = 'action_bridge_endpoint'
    id = Column(Integer, primary_key=True)
    action_id = Column(Integer, ForeignKey('action.id', onupdate='CASCADE', \
                                                            ondelete='CASCADE'))
    endpoint = Column(types.UnicodeText)
    action = relationship('Action')
    __table_args__ = (
                UniqueConstraint('action_id', 'endpoint', name='action_id_endpoint_key'),
                {}
                )

    def __init__(self, action_id, endpoint):
        self.action_id = action_id
        self.endpoint = endpoint

    def get_by_id(request, endpoint_id):
        try:
            endpoint = request.dbsession.query(ActionBridgeEndpoint).filter(ActionBridgeEndpoint.id == endpoint_id).one()
            return endpoint
        except orm_exc.NoResultFound:
            log.debug('ActionBridgeEndpoint.get_by_id couldn\' find given id {0}'.format(endpoint_id))
            return None
        except Exception as e:
            log.debug('ActionBridgeEndpoint.get_by_id with endpoint_id {0} failed with Error: {1}'.format(endpoint_id, e))
            raise

    def reprJSON(self, cmdData=list()):
        log.debug(self.endpoint)
        cmdData.append({"target":self.endpoint, "action_bridge_endpoint_id":self.id, "type":"endpoint"})
        return cmdData 



class ApplicationCatalog(Base):
    __tablename__ = 'application_catalog'
    id = Column(Integer, primary_key=True)
    command = Column(types.UnicodeText, unique=True)
    data_template = Column(types.UnicodeText)
    actions = relationship('Action', back_populates="application_catalog", cascade="all, delete-orphan")

    def __init__(self, application_name, data_template):
        self.application_name = application_name
        self.data_template = data_template

    def get_by_id(request, application_catalog_id):
        try:
            application = request.dbsession.query(ApplicationCatalog).filter(ApplicationCatalog.id == application_catalog_id).one()
            return application
        except Exception as e:
            log.debug('ApplicationCatalog.get_by_id failed with {0} for id {1}'.format(e, application_catalog_id))
            raise


    def get_by_command(request, command):
        try:
            application = request.dbsession.query(ApplicationCatalog).filter(ApplicationCatalog.command == command).one()
            return application
        except Exception as e:
            log.debug('ApplicationCatalog.get_by_command failed with {0}'.format(e))
            raise

    def get_applications(request):
        try:
            applications = request.dbsession.query(ApplicationCatalog).all()
            return applications
        except Exception as e:
            log.debug('ApplicationCatalog.get_applications failed with {0}'.format(e))
            raise

    def reprJSON(self):
        try:
            return dict(application_catalog_id=self.id, command=self.command, data_template=self.data_template) 
        except AttributeError:
            return dict()




        



#class RootFactory(object):
#    def __init__(self, request):
#        self.request = request
#    
#    def __acl__(self):
#        rootfactory_acl = [
#            (Allow, 'g:admin', ALL_PERMISSIONS),
#            (Allow, 'g:editors', 'edit'),
#            ]
#        log.debug(rootfactory_acl)
#        return rootfactory_acl


ziggurat_model_init(User, Group, UserGroup, GroupPermission, UserPermission,
               UserResourcePermission, GroupResourcePermission, Resource,
               ExternalIdentity, passwordmanager=None)
