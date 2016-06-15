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
    Unicode
)

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.dialects import postgresql

from sqlalchemy.orm import (
    scoped_session,
    sessionmaker,
    relationship,
    backref
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
from ziggurat_foundations.models.base import BaseModel
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

#users_groups_table = Table('users_groups', Base.metadata,
#    Column('user_id', Integer, ForeignKey('users.id', onupdate="CASCADE", ondelete="CASCADE"), primary_key=True),
#    Column('group_id', Integer, ForeignKey('groups.id',onupdate="CASCADE", ondelete="CASCADE"), primary_key=True),
#    UniqueConstraint('user_id', 'group_id', name='user_id_group_id'))


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
    pass

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
#    groups = relationship('Group', secondary=users_groups_table, backref='memberships')


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
    #users = relationship('User', secondary=users_groups_table, backref='members')

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



class Extension(Base):

    __tablename__ = 'extension'
    id = Column(Integer, primary_key=True)
    extension = Column(types.UnicodeText, unique=True)
    domain_id = Column(Integer, ForeignKey('domain.id', onupdate='CASCADE', \
                            ondelete='CASCADE'))
    routes = relationship('Route')

    def __init__(self, extension, domain_id):
        self.extension = extension
        self.domain_id = domain_id

    def routesJSON(self):
        routes = self.routes


class Route(Resource):
    __tablename__ = 'route'
    __mapper_args__ = {'polymorphic_identity': 'route'}
    id = Column(Integer, primary_key=True)
    resource_id = Column(Integer, ForeignKey('resources.resource_id', onupdate='CASCADE', \
                                                     ondelete='CASCADE')) 
    extension_id = Column(Integer, ForeignKey('extension.id', onupdate='CASCADE', \
                                                              ondelete='CASCADE'))
    sequences = relationship('Sequence', order_by='asc(Sequence.sequence)')

    def reprJSON(self):
        sequences = [sequence.reprJSON() for sequence in self.sequences]
        return sequences


class Sequence(Base):
    __tablename__ = 'sequence'
    id = Column(Integer, primary_key=True)
    route_id = Column(Integer, ForeignKey('route.id', onupdate='CASCADE', \
                                                      ondelete='CASCADE'))
    sequence = Column(Integer)
    timeout = Column(Integer, default=20)
    action = relationship('Action', uselist=False, back_populates='sequence')
    __table_args__ = (
            UniqueConstraint('route_id', 'sequence', name='route_id_sequence_key'),
            {}
            )

    def reprJSON(self):
        command = self.action.application.application_catalog.command
        data = self.action.application.application_data
        return dict(data=data, command=command, sequence=self.sequence)

class Action(Base):
    __tablename__ = 'action'
    id = Column(Integer, primary_key=True)
    sequence_id = Column(Integer, ForeignKey('sequence.id', onupdate='CASCADE', \
                                                            ondelete='CASCADE'))
    active = Column(types.Boolean, default=True)
    sequence = relationship('Sequence')
    application = relationship('ActionApplication', uselist=False, back_populates='action')



class ActionApplication(Base):
    __tablename__ = 'action_application'
    id = Column(Integer, primary_key=True)
    action_id = Column(Integer, ForeignKey('action.id', onupdate='CASCADE', \
                                                       ondelete='CASCADE'))
    application_id = Column(Integer, ForeignKey('application_catalog.id', onupdate='CASCADE', \
                                                                  ondelete='CASCADE'))
    application_data = Column(types.UnicodeText)
    action = relationship('Action', back_populates='application')
    application_catalog = relationship('ApplicationCatalog')



class ApplicationCatalog(Base):
    __tablename__ = 'application_catalog'
    id = Column(Integer, primary_key=True)
    command = Column(types.UnicodeText, unique=True)
    data_template = Column(types.UnicodeText)
    actions = relationship('ActionApplication', back_populates="application_catalog")

    def __init__(self, application_name, data_template):
        self.application_name = application_name
        self.data_template = data_template



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
