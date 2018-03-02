# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
import re
import bcrypt 
from datetime import datetime

NAME_REGEX = re.compile(r"^[a-zA-Z-' ]+$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$")
PASS_REGEX = re.compile(r"^[a-zA-Z0-9.+_-]{8,}$")


class UserManager(models.Manager):
    def register(self, post_data):
        errors = []

        if len(post_data['email']) < 1:
            errors.append("Email cannot be left blank!")
        elif not EMAIL_REGEX.match(post_data['email']):
            errors.append("Invalid characters in email")
        check_email = User.objects.filter(email = post_data['email'])
        if len(check_email) > 0:
            errors.append("Email already exists")

        if len(post_data['first_name']) < 1:
            errors.append("First Name cannot be left blank!")
        elif len(post_data['first_name']) < 2:
            errors.append("First Name must be at least 2 characters long")
        if not NAME_REGEX.match(post_data['first_name']):
            errors.append("Invalid characters in First Name")

        if len(post_data['last_name']) < 1:
            errors.append("Last Name cannot be left blank!")
        elif len(post_data['last_name']) < 2:
            errors.append("Last Name must be at least 2 characters long")
        if not NAME_REGEX.match(post_data['last_name']):
            errors.append("Invalid characters in Last Name")

        if len(post_data['password']) < 1:
            errors.append("Password cannot be left blank!")
        elif len(post_data['password']) < 8:
            errors.append("Password should be at least 8 characters")
        if not PASS_REGEX.match(post_data['password']):
            errors.append("Invalid characters in Password")
        if post_data['password'] != post_data['confirm']:
            errors.append("Passwords do not match!")
                
        if len(errors) > 0:
            return (False, errors)
        else: 
            user = User.objects.create(
                email = post_data['email'],
                first = post_data['first_name'],
                last = post_data['last_name'],
                password = bcrypt.hashpw(post_data['password'].encode(), bcrypt.gensalt()),
                user_level = 1
            )
            if user.id == 1:
                user.user_level = 9
                user.save()
            return(True, user)

    def login(self, post_data):
        errors = []

        if len(post_data['password']) < 1:
            errors.append("Password cannot be left blank!")
        elif len(post_data['password']) < 8:
            errors.append("Password should be at least 8 characters")
        if not PASS_REGEX.match(post_data['password']):
            errors.append("Invalid characters in Password")

        if len(post_data['email']) < 1:
            errors.append("Email cannot be left blank!")
        if not EMAIL_REGEX.match(post_data['email']):
            errors.append("Invalid characters in email")
        check_email = User.objects.filter(email = post_data['email'])
        if len(check_email) == 0:
            errors.append("Email does not exist")

        if len(errors) > 0:
            return (False, errors)
        else:
            user = check_email[0]
            if not bcrypt.checkpw(post_data["password"].encode(), user.password.encode()):
                errors.append("Invalid Password")

            if len(errors) > 0:
                return (False, errors)
            else: 
                return(True, user)

    def edituser(self, post_data, user_id, logged_id):
        errors = []

        if not EMAIL_REGEX.match(post_data['email']):
            errors.append("Invalid characters in email")
        check_email = User.objects.filter(email = post_data['email'])
        if len(check_email) > 0:
            if check_email[0].id != int(user_id):
                errors.append("Email already exists")
        if len(post_data['first_name']) < 2:
            errors.append("First Name must be at least 2 characters long")
        if not NAME_REGEX.match(post_data['first_name']):
            errors.append("Invalid characters in First Name")

        if len(post_data['last_name']) < 2:
            errors.append("Last Name must be at least 2 characters long")
        if not NAME_REGEX.match(post_data['last_name']):
            errors.append("Invalid characters in Last Name")
                
        if len(errors) > 0:
            return (False, errors)
        else: 
            user = User.objects.get(id=user_id)
            user.email = post_data['email']
            user.first = post_data['first_name']
            user.last = post_data['last_name']
            if 'level' in post_data:
                if post_data['level'] == "Admin":
                    user.user_level = 9
                else: 
                    user.user_level = 1
            user.save()
            return(True, user)

    def editpwd(self, post_data, user_id):
        errors = []

        if len(post_data['password']) < 1:
            errors.append("Password cannot be left blank!")
        elif len(post_data['password']) < 8:
            errors.append("Password should be at least 8 characters")
        if not PASS_REGEX.match(post_data['password']):
            errors.append("Invalid characters in Password")
        if post_data['password'] != post_data['confirm']:
            errors.append("Passwords do not match!")
                
        if len(errors) > 0:
            return (False, errors)
        else: 
            user = User.objects.get(id=user_id)
            user.password = bcrypt.hashpw(post_data['password'].encode(), bcrypt.gensalt())
            user.save()
            return(True, user)

    def editdesc(self, post_data, user_id):
        errors = []
        if len(post_data['desc']) < 1:
            errors.append("Description cannot be left blank!")
                
        if len(errors) > 0:
            return (False, errors)
        else: 
            user = User.objects.get(id=user_id)
            user.desc = post_data['desc']
            user.save()
            return(True, user)

class User(models.Model):
    email = models.CharField(max_length=255)
    first = models.CharField(max_length=255)
    last = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    user_level = models.PositiveSmallIntegerField()
    desc = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

class MCManager(models.Manager):
    def msg_valid(self, post_data, user_id, poster_id):
        errors = []
        if len(post_data['text']) < 1:
            errors.append("Message cannot be left blank!")

        if len(errors) > 0:
            return (False, errors)
        else: 
            text = Message.objects.create(
                message = post_data['text'],
                sender = User.objects.get(id=poster_id),
                receiver = User.objects.get(id=user_id),
            )
            return(True, text)

    def cmt_valid(self, post_data, msg_id, poster_id):
        errors = []
        if len(post_data['text']) < 1:
            errors.append("Message cannot be left blank!")

        if len(errors) > 0:
            return (False, errors)
        else: 
            text = Comment.objects.create(
                comment = post_data['text'],
                msg = Message.objects.get(id=msg_id),
                commenter = User.objects.get(id=poster_id),
            )
            return(True, text)

class Message(models.Model):
    message = models.TextField()
    sender = models.ForeignKey(User, related_name="msgs_made")
    receiver = models.ForeignKey(User, related_name="poster")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = MCManager()

class Comment(models.Model):
    comment = models.TextField()
    msg = models.ForeignKey(Message, related_name="comments")
    commenter = models.ForeignKey(User, related_name="cmts_made")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = MCManager()