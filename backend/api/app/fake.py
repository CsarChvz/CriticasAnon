from random import randint
from sqlalchemy.exc import IntegrityError
from faker import Faker
from . import db
from .models import User, Post, Profile

def users(count=100):
    fake = Faker()
    i = 0
    while i < count:
        u = User(email=fake.email(), username=fake.user_name(), password='password', confirmed=True, role_id=randint(1, 3))
        db.session.add(u)
        try:
            db.session.commit()
            i += 1
        except IntegrityError:
            db.session.rollback()


def profiles(count=100):
    fake = Faker()
    user_count = User.query.count()

    for i in range(count):
        #u = User.query.filter_by(id=i)
        u = User.query.offset(i).first()
        print(i, user_count)
        print(u)
        pr = Profile(last_name=fake.last_name(),first_name = fake.first_name(),location=fake.city(), about_me=fake.text(), member_since=fake.past_date(), last_seen=fake.past_date(), user_id=u.id)

        #pr = Profile(location=fake.city(), about_me=fake.text(), member_since=fake.past_date(), last_seen=fake.past_date(), user_id=u)
        db.session.add(pr)
    db.session.commit()


# Tenemos que agregar posts a los perfiles
def posts(count=100):
    fake = Faker()
    user_count = User.query.count()
    profile_count = Profile.query.count()
    for i in range(count):
        # Tenemos que 
        u = User.query.offset(randint(0, user_count - 1)).first()
        pr = Profile.query.offset(randint(0, profile_count - 1)).first()
        p = Post(body=fake.text(), timestamp=fake.past_date(), user_id=u.id, profile_id=pr.id)
        db.session.add(p)
    db.session.commit()