#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User
import bcrypt


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        The method should save the user to the database.
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """
        This method takes in arbitrary keyword arguments and returns
        the first row found in the users table as filtered
        by the method’s input arguments
        """
        try:
            result = self._session.query(User).filter_by(**kwargs).first()
            if result is None:
                self._session.rollback()
                raise NoResultFound
            return result
        except InvalidRequestError as e:
            self._session.rollback()
            raise e

    def update_user(self, user_id: int, **kwargs) -> None:
        """
         method that takes as argument a required user_id integer and
         arbitrary keyword arguments, and returns None
        """
        user = self.find_user_by(id=user_id)
        for key in kwargs.keys():
            if not hasattr(user, key):
                raise ValueError
        for key, value in kwargs.items():
            setattr(user, key, value)
        self._session.commit()
