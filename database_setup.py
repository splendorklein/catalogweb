from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    
class Categories(Base):
    __tablename__ = 'categories'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
       }
 
class Items(Base):
    __tablename__ = 'items'


    name =Column(String(80), nullable = True)
    id = Column(Integer, primary_key = True)
    description = Column(String(250))
    
    category_name = Column(String(80),ForeignKey('categories.name'))
    
    categories_name = relationship(Categories,foreign_keys=[category_name])


    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'description'  : self.description,
           'id'           : self.id,
           'category_name': self.category_name,
       }



engine = create_engine('sqlite:///catalog.db')
 

Base.metadata.create_all(engine)
