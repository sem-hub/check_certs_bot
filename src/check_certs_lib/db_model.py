'''
DB model to work with SQL Alchemy
'''

from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship


Base = declarative_base()

class Servers(Base):
    '''Save a list of URLs to check and all info about them'''
    __tablename__ = 'servers'

    id = Column(Integer, primary_key=True)
    when_added = Column(String, default=datetime.utcnow)
    url = Column(String)
    chat_id = Column(String, ForeignKey('users.id'))
    warn_before_expired = Column(Integer, default=5)
    last_checked = Column(String, default='')
    last_ok = Column(String, default='')
    status = Column(String, default='')
    cert_id = Column(String, default='')

    user = relationship('Users')

    def __repr__(self):
        return (f'<Servers(when_added={self.when_added!r}, '
                f'url={self.url!r}, '
                f'chat_id={self.chat_id!r}, '
                f'warn_before_expired={self.warn_before_expired}, '
                f'last_checked={self.last_checked!r}, '
                f'last_ok={self.last_ok!r}, '
                f'status={self.status!r}, '
                f'cert_id={self.cert_id!r})>')

class Users(Base):
    '''Save users info'''
    __tablename__ = 'users'

    id = Column(String, primary_key=True)
    name = Column(String)
    full_name = Column(String)
    language_code = Column(String)
    timezone = Column(Integer, default=0)
    first_met = Column(String, default=datetime.utcnow)
    last_activity = Column(String, default='')
    status = Column(String, default='')

    def __repr__(self):
        return (f'<Users(id={self.id!r}, '
                f'name={self.name!r}, '
                f'full_name={self.full_name!r}, '
                f'language_code={self.language_code!r}, '
                f'first_met={self.first_met!r}, '
                f'last_activity={self.last_activity!r}, '
                f'status={self.status!r})>')

class Activity(Base):
    '''Save user activities'''
    __tablename__ = 'activity'

    id = Column(Integer, primary_key=True)
    user_id = Column(String, ForeignKey('users.id'))
    cmd = Column(String)
    date = Column(String, default=datetime.utcnow)

    user = relationship('Users')

    def __repr__(self):
        return (f'<Activity(id={self.id}, '
                f'user_id={self.user_id!r}, '
                f'cmd={self.cmd!r}, '
                f'date={self.date!r})>')

class DB:
    '''Simple class to hide SQL Alchemy specifics'''
    def __init__(self, db_url: str):
        self.engine = create_engine(db_url, echo=False)

    def create_db(self):
        '''Cread DB is don't have yet'''
        Base.metadata.create_all(self.engine)

    def get_session(self):
        '''Make a new session and return it'''
        Session = sessionmaker(bind=self.engine)
        return Session()
