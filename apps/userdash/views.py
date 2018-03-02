# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render, redirect
from .models import User, Message, Comment
from django.contrib import messages


def index(request):
    return render(request, 'userdash/index.html')

def signin(request):
    return render(request, 'userdash/signin.html')

def login(request):
    signin_info = User.objects.login(request.POST)
    if signin_info[0]: 
        request.session['logged_id'] = signin_info[1].id 
        return redirect('/dashboard')
    else: 
        for error in signin_info[1]:
            messages.add_message(request, messages.ERROR, error)
        return redirect('/signin')

def register(request):
    return render(request, 'userdash/register.html')

def user_create(request):
    reg_info = User.objects.register(request.POST)
    if reg_info[0]:
        if 'logged_id' not in request.session:
            request.session['logged_id'] = reg_info[1].id
            return redirect('/dashboard')
        else: 
            admin = User.objects.get(id=request.session['logged_id'])
            if admin.user_level != 9:
                return redirect('/users/new')
    else: 
        for error in reg_info[1]:
            messages.add_message(request, messages.ERROR, error)
            if 'logged_id' not in request.session:
                return redirect('/register')
            else: 
                admin = User.objects.get(id=request.session['logged_id'])
                if admin.user_level != 9:
                    return redirect('/users/new')

def dashboard(request):
    if 'logged_id' not in request.session:
        return redirect('/')
    admin = User.objects.get(id=request.session['logged_id'])
    if admin.user_level == 9:
        return redirect('/dashboard/admin')
    data = {
        "user": User.objects.get(id=request.session['logged_id']),
        "allusers": User.objects.all(),
    }
    return render(request, 'userdash/dashboard.html', data)

def admin_dash(request):
    if 'logged_id' not in request.session:
        return redirect('/')
    user = User.objects.get(id=request.session['logged_id'])
    if user.user_level != 9:
        return redirect('/dashboard')
    data = {
        "user": user,
        "allusers": User.objects.all(),
    }
    return render(request, 'userdash/admindash.html', data)

def show(request, user_id):
    if 'logged_id' not in request.session:
        return redirect('/')
    data = {
        "logged": User.objects.get(id=request.session['logged_id']),
        "user": User.objects.get(id=user_id),
        "posted": Message.objects.filter(receiver = User.objects.get(id=user_id)),
        "commented": Comment.objects.all()
    }
    return render(request, 'userdash/profile.html', data)

def admin_new(request):
    if 'logged_id' not in request.session:
        return redirect('/')
    admin = User.objects.get(id=request.session['logged_id'])
    if admin.user_level != 9:
        return redirect('/dashboard')
    data = {
        "user": User.objects.get(id=admin.id),
    }
    return render(request, 'userdash/adminnew.html', data)

def admin_create(request):
    reg_info = User.objects.register(request.POST)
    if reg_info[0]:
        return redirect('/users/new')
    else: 
        for error in reg_info[1]:
            messages.add_message(request, messages.ERROR, error)
            return redirect('/users/new')

def admin_edit(request, user_id):
    if 'logged_id' not in request.session:
        return redirect('/')
    admin = User.objects.get(id=request.session['logged_id'])
    if admin.user_level != 9:
        return redirect('/users/edit')
    data = {
        "admin": User.objects.get(id=admin.id),
        "user": User.objects.get(id=user_id),
    }
    return render(request, 'userdash/adminedit.html', data)

def user_edit(request):
    if 'logged_id' not in request.session:
        return redirect('/')
    data = {
        "user": User.objects.get(id=request.session['logged_id'])
    }
    return render(request, 'userdash/useredit.html', data)

def edit(request, user_id):
    logged_id = request.session['logged_id']
    edituser_info = User.objects.edituser(request.POST, user_id, logged_id)
    if edituser_info[0]: 
        admin = User.objects.get(id=logged_id)
        if admin.user_level == 9:
            return redirect('/dashboard/admin')
        else:
            request.session['logged_id'] = edituser_info[1].id 
            return redirect('/users/show/'+str(user_id))
    else: 
        for error in edituser_info[1]:
            messages.add_message(request, messages.ERROR, error)
            admin = User.objects.get(id=request.session['logged_id'])
            if admin.user_level == 9:
                return redirect('/users/edit/'+str(user_id))
            else: 
                return redirect('/users/edit')

def password(request, user_id):
    editpass_info = User.objects.editpwd(request.POST, user_id)
    if editpass_info[0]: 
        return redirect('/users/show/'+str(user_id))
    else: 
        for error in editpass_info[1]:
            messages.add_message(request, messages.ERROR, error)
        user = User.objects.get(id=request.session['logged_id'])
        if user.user_level == 9:
            return redirect('/users/edit/'+str(user_id))
        else:
            return redirect('/users/edit')

def description(request, user_id):
    editdesc_info = User.objects.editdesc(request.POST, user_id)
    if editdesc_info[0]: 
        return redirect('/users/show/'+str(user_id))
    else: 
        for error in editdesc_info[1]:
            messages.add_message(request, messages.ERROR, error)
        return redirect('/users/edit')

def post_msg(request, user_id):
    poster = User.objects.get(id=request.session['logged_id'])
    poster_id = poster.id
    msg_info = Message.objects.msg_valid(request.POST, user_id, poster_id)
    if msg_info[0]: 
        return redirect('/users/show/'+str(user_id))
    else: 
        for error in msg_info[1]:
            messages.add_message(request, messages.ERROR, error)
        return redirect('/users/show/'+str(user_id))

def post_cmt(request, user_id, msg_id):
    poster_id = User.objects.get(id=request.session['logged_id']).id
    cmt_info = Comment.objects.cmt_valid(request.POST, msg_id, poster_id)
    if cmt_info[0]: 
        return redirect('/users/show/'+str(user_id))
    else: 
        for error in cmt_info[1]:
            messages.add_message(request, messages.ERROR, error)
        return redirect('/users/show/'+str(user_id))

def logoff(request):
    request.session.clear()
    return redirect('/')

def delete(request, user_id):
    user = User.objects.get(id=user_id)
    user.delete()
    return redirect('/dashboard')