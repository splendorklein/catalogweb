from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
 
from database_setup import Categories, Base, Items
 
engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine
 
DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

#Menu for UrbanBurger
category1 = Categories(name = "Soccer")
category2 = Categories(name = "Basketball")
category3 = Categories(name = "Baseball")
category4 = Categories(name = "Frisbee")
category5 = Categories(name = "Snowboarding")
category6 = Categories(name = "Football")
category7 = Categories(name = "Skating")


session.add(category1)
session.add(category2)
session.add(category3)
session.add(category4)
session.add(category5)
session.add(category6)
session.add(category7)
session.commit()


item1 = Items(name = "Jersey", description = "A jersey is an item of"
" knitted clothing, traditionally in wool or cotton, with sleeves, worn"
" as a pullover, as it does not open at the front, unlike a cardigan. It "
"is usually close-fitting and machine knitted in contrast to a guernsey "
"that is more often hand knit with a thicker yarn."
,categories_name = category1)

item2 = Items(name = "Football Boot", description = "Football boots, called"
" cleats or soccer shoes in North America, are an item of footwear worn when"
" playing football. Those designed for grass pitches have studs on the outsol"
"e to aid grip.",categories_name = category1)

item3 = Items(name = "Shin Guard", description = "A shin guard or shin pad "
"is a piece of equipment worn on the front of a player's shin to protect"
" them from injury.",categories_name = category1)


item4 = Items(name = "Sleeve", description = "A basketball sleeve, like "
	"the wristband, is an accessory that basketball players wear. Made "
	"out of nylon and spandex, it extends from the biceps to the wrist."
	,categories_name = category2)

session.add(item1)
session.add(item2)
session.add(item3)
session.add(item4)
session.commit()

print "added all items!"

