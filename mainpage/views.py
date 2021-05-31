import random
import re
from datetime import datetime

import bcrypt
from django.db import DataError
from django.db.models import Q
from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.csrf import csrf_exempt
from docxtpl import DocxTemplate

from .models import ProgramWork, Users, Favorites


def index(request):
    latest_program_list = ProgramWork.objects.all()
    if 'user_session' in request.session:
        favours_program_list = list(
            Favorites.objects.all().filter(user_id=request.session['user_id']).values_list('program_id', flat=True))
        return render(request, 'mainpage/index.html',
                      {'username': request.session['username'], 'status': request.session['status'],
                       'user_id': request.session['user_id'], 'latest_program_list': latest_program_list,
                       'favours_program_list': favours_program_list})
    else:
        return render(request, 'mainpage/index.html', {'latest_program_list': latest_program_list})


def filtr(request):
    latest_program_list = ProgramWork.objects.all()
    if request.method == "POST":
        if len(request.POST['direction']) > 50:
            direction = ''
        else:
            direction = request.POST.get('direction')

        # employment
        employmentfull = request.POST.get('employmentfull')
        employmentpart = request.POST.get('employmentpart')
        if employmentfull == 'on':
            employmentfull = 'полн'
        else:
            employmentfull = ' '
        if employmentpart == 'on':
            employmentpart = 'част'
        else:
            employmentpart = ' '
        queryemployment = (Q(program_employment__icontains=employmentfull) &
                           Q(program_employment__icontains=employmentpart))
        if (employmentfull == 'полн') & (employmentpart == 'част'):
            queryemployment = (Q(program_employment__icontains=employmentfull) |
                               Q(program_employment__icontains=employmentpart))
        # during
        duringsixmonth = request.POST.get('duringsixmonth')
        duringsixmonthyear = request.POST.get('duringsixmonthyear')
        duringonethreeyear = request.POST.get('duringonethreeyear')
        queryduring = ''
        if duringsixmonth == 'on':
            queryduring = (Q(program_during__icontains='месяц') &
                           Q(program_during__icontains='1') |
                           Q(program_during__icontains='2') |
                           Q(program_during__icontains='3') |
                           Q(program_during__icontains='4') |
                           Q(program_during__icontains='5'))
        if duringsixmonthyear == 'on':
            queryduring = (Q(program_during__icontains='месяц') &
                           Q(program_during__icontains='6') |
                           Q(program_during__icontains='7') |
                           Q(program_during__icontains='8') |
                           Q(program_during__icontains='9') |
                           Q(program_during__icontains='10') |
                           Q(program_during__icontains='11') |
                           Q(program_during__icontains='12'))
        if duringonethreeyear == 'on':
            queryduring = (Q(program_during__icontains='год') | Q(program_during__icontains='12'))
        if (duringsixmonth != 'on') & (duringsixmonthyear != 'on') & (duringonethreeyear != 'on'):
            queryduring = Q()

        # paying
        payingpay = request.POST.get('payingpay')
        payingunpay = request.POST.get('payingunpay')
        if payingunpay == 'on':
            querypaying = (Q(program_paying__icontains='не'))
        else:
            if payingpay == 'on':
                querypaying = (~Q(program_paying__icontains='не'))
            else:
                querypaying = Q()
        if (payingunpay == 'on') & (payingpay == 'on'):
            querypaying = Q()
        latest_program_list = ProgramWork.objects.filter(Q(program_direction__icontains=direction) &
                                                         queryemployment & queryduring & querypaying)
    if 'user_session' in request.session:
        favours_program_list = list(
            Favorites.objects.all().filter(user_id=request.session['user_id']).values_list('program_id', flat=True))
        return render(request, 'mainpage/index.html',
                      {'username': request.session['username'], 'status': request.session['status'],
                       'user_id': request.session['user_id'], 'latest_program_list': latest_program_list,
                       'favours_program_list': favours_program_list})
    else:
        return render(request, 'mainpage/index.html', {'latest_program_list': latest_program_list})


def detail(request, program_id):
    program = get_object_or_404(ProgramWork, pk=program_id)
    direction_list = program.program_direction.split(';')
    requirement_list = program.program_requirement.split(';')
    if 'user_session' in request.session:
        return render(request, "mainpage/detail.html", {'program': program, 'username': request.session['username'],
                                                        'status': request.session['status'],
                                                        'direction_list': direction_list,
                                                        'requirement_list': requirement_list})
    else:
        return render(request, "mainpage/detail.html", {'program': program, 'direction_list': direction_list,
                                                        'requirement_list': requirement_list})


@csrf_exempt
def login(request):
    messagepassword = ''
    if request.method == 'POST':
        # check length
        if len(request.POST['username']) < 5 or len(request.POST['username']) > 30:
            messageusername = 'Логин должен быть не менее 5 символов'
            if len(request.POST['password']) < 6 or len(request.POST['password']) > 60:
                messagepassword = 'Пароль должен быть не менее 6 символов'
            return render(request, 'mainpage/login.html', {'messageusername': messageusername, 'username': request.POST['username'],
                                                           'messagepassword': messagepassword, 'password': request.POST['password']})
        users = Users.objects.all().filter(user_username=request.POST['username'])
        if users.count() == 0:
            message = 'Ошибка входа'
            return render(request, 'mainpage/login.html', {'message': message})
        else:
            for user in users:
                password = request.POST['password'].encode('utf-8')
                # check hash
                if bcrypt.checkpw(password, bytes(user.user_password)):
                    request.session['user_session'] = random.random()
                    request.session['username'] = request.POST['username']
                    request.session['user_id'] = user.id
                    if user.user_status:
                        request.session['status'] = 'true'
                    else:
                        request.session['status'] = 'false'
                    favours_program_list = list(
                        Favorites.objects.all().filter(user_id=request.session['user_id']).values_list('program_id', flat=True))
                    latest_program_list = ProgramWork.objects.all()
                    return render(request, 'mainpage/index.html',
                                            {'username': request.session['username'], 'status': request.session['status'],
                                             'user_id': request.session['user_id'], 'latest_program_list': latest_program_list,
                                             'favours_program_list': favours_program_list})
                else:
                    message = 'Ошибка входа'
                    return render(request, 'mainpage/login.html', {'message': message})
    else:
        return render(request, 'mainpage/login.html')


@csrf_exempt
def logout(request):
    try:
        del request.session['user_session']
        del request.session['username']
        del request.session['status']
        del request.session['user_id']
    except KeyError:
        pass
    latest_program_list = ProgramWork.objects.all()
    return render(request, 'mainpage/index.html', {'latest_program_list': latest_program_list})


@csrf_exempt
def registr(request):
    messageusername = ''
    messagepassword = ''
    messageaddress = ''
    messagefio = ''
    if request.method == 'POST':
        if len(request.POST['username']) < 5 or len(request.POST['username']) > 30:
            messageusername = "Логин должен быть не менее 5 символов"
            if len(request.POST['password']) < 6 or len(request.POST['password']) > 60:
                messagepassword = "Пароль должен быть не менее 6 символов"
                if len(request.POST['address']) < 4 or len(request.POST['address']) > 50:
                    messageaddress = "Ошибка ввода адреса электронной почты"
                    if len(request.POST['fio']) > 50:
                        messagefio = "Ошибка ввода ФИО"
            return render(request, 'mainpage/registr.html',
                          {'messageusername': messageusername, 'username': request.POST['username'],
                           'messagepassword': messagepassword, 'password': request.POST['password'],
                           'messageaddress': messageaddress, 'address': request.POST['address'],
                           'messagefio': messagefio, 'fio': request.POST['fio']})
        if re.search(r"[\w._%+-]+@[\w.-]+\.[a-zA-Z]{2,4}", request.POST['address']):
            if re.search(r"^[А-ЯЁа-яё\s]+$", request.POST['fio']):
                usernames = Users.objects.all().filter(user_username=request.POST['username'])
                useraddresses = Users.objects.all().filter(user_address=request.POST['address'])
                if usernames.count() != 0 or useraddresses.count() != 0:
                    message = 'Пользователь с такими данными уже существует в системе'
                    return render(request, 'mainpage/registr.html', {'message': message,
                                                                 'messageusername': messageusername,
                                                                 'username': request.POST['username'],
                                                                 'messagepassword': messagepassword,
                                                                 'password': request.POST['password'],
                                                                 'messageaddress': messageaddress,
                                                                 'address': request.POST['address'],
                                                                 'messagefio': messagefio, 'fio': request.POST['fio']})
                else:
                    new_user = Users()
                    new_user.user_name = request.POST.get("fio")
                    new_user.user_address = request.POST.get("address")
                    new_user.user_username = request.POST.get("username")
                    new_user.user_status = False
                    # hashed
                    password = request.POST.get("password").encode('utf-8')
                    hashedpassword = bcrypt.hashpw(password, bcrypt.gensalt())
                    new_user.user_password = hashedpassword
                    new_user.save()
                    # session
                    request.session['user_session'] = random.random()
                    request.session['username'] = new_user.user_username
                    request.session['status'] = 'false'
                    request.session['user_id'] = new_user.id
                    latest_program_list = ProgramWork.objects.all()
                    return render(request, 'mainpage/index.html',
                                  {'username': request.session['username'], 'status': request.session['status'],
                                   'user_id': request.session['user_id'], 'latest_program_list': latest_program_list})
            else:
                messagefio = "Ошибка ввода ФИО"
                return render(request, 'mainpage/registr.html',
                              {'messageusername': messageusername, 'username': request.POST['username'],
                               'messagepassword': messagepassword, 'password': request.POST['password'],
                               'messageaddress': messageaddress, 'address': request.POST['address'],
                               'messagefio': messagefio, 'fio': request.POST['fio']})
        else:
            messageaddress = "Ошибка ввода адреса электронной почты"
            return render(request, 'mainpage/registr.html',
                          {'messageusername': messageusername, 'username': request.POST['username'],
                           'messagepassword': messagepassword, 'password': request.POST['password'],
                           'messageaddress': messageaddress, 'address': request.POST['address'],
                           'messagefio': messagefio, 'fio': request.POST['fio']})
    else:
        return render(request, 'mainpage/registr.html')


@csrf_exempt
def add(request):
    messagename = ''
    messagepicture = ''
    messagedescribe = ''
    messageduring = ''
    messageemployment = ''
    messagedirection = ''
    messagerequirement = ''
    messagecontact = ''
    messagepaying = ''
    messagetiming = ''
    if request.method == 'POST':
        pw = ProgramWork()
        try:
            pw.program_name = request.POST.get("name")
            pw.save()
        except DataError:
            messagename = "Ошибка ввода названия"
            ProgramWork.objects.filter(program_name=pw.program_name).delete()
            return render(request, 'mainpage/addprogram.html',
                          {'username': request.session['username'],
                           'messagename': messagename, 'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        pw.program_picture = request.FILES.get("picture")
        picture = str(pw.program_picture).lower().split('.')
        typepicture = picture[-1]
        if typepicture == "jpg" or typepicture == "png" or typepicture == "jpeg":
            pw.save()
        else:
            messagepicture = "Неверный формат изображения"
            ProgramWork.objects.filter(program_name=pw.program_name).delete()
            return render(request, 'mainpage/addprogram.html',
                          {'username': request.session['username'],
                           'messagename': messagename, 'messagepicture': messagepicture,
                           'program_name': request.POST.get("name"),
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_describe = request.POST.get("describe")
            pw.save()
        except DataError:
            messagedescribe = "Ошибка ввода описания"
            ProgramWork.objects.filter(program_name=pw.program_name).delete()
            return render(request, 'mainpage/addprogram.html',
                          {'username': request.session['username'],
                           'messagename': messagename, 'program_name': request.POST.get("name"),
                           'messagepicture': messagepicture, 'messagedescribe': messagedescribe,
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_during = request.POST.get("during")
            pw.save()
        except DataError:
            messageduring = "Ошибка ввода продолжительности"
            ProgramWork.objects.filter(program_name=pw.program_name).delete()
            return render(request, 'mainpage/addprogram.html',
                          {'username': request.session['username'],
                           'messagename': messagename, 'program_name': request.POST.get("name"),
                           'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring,
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_employment = request.POST.get("employment")
            pw.save()
        except DataError:
            messageemployment = "Ошибка ввода типа занятости"
            ProgramWork.objects.filter(program_name=pw.program_name).delete()
            return render(request, 'mainpage/addprogram.html',
                          {'username': request.session['username'],
                           'messagename': messagename, 'program_name': request.POST.get("name"),
                           'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment,
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_direction = request.POST.get("direction")
            pw.save()
        except DataError:
            messagedirection = "Ошибка ввода направлений"
            ProgramWork.objects.filter(program_name=pw.program_name).delete()
            return render(request, 'mainpage/addprogram.html',
                          {'username': request.session['username'],
                           'messagename': messagename, 'program_name': request.POST.get("name"),
                           'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection,
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_requirement = request.POST.get("requirement")
            pw.save()
        except DataError:
            messagerequirement = "Ошибка ввода требований"
            ProgramWork.objects.filter(program_name=pw.program_name).delete()
            return render(request, 'mainpage/addprogram.html',
                          {'username': request.session['username'],
                           'messagename': messagename, 'program_name': request.POST.get("name"),
                           'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_contact = request.POST.get("contact")
            pw.save()
        except DataError:
            messagecontact = "Ошибка ввода контактов"
            ProgramWork.objects.filter(program_name=pw.program_name).delete()
            return render(request, 'mainpage/addprogram.html',
                          {'username': request.session['username'],
                           'messagename': messagename, 'program_name': request.POST.get("name"),
                           'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact,
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_timing = request.POST.get("timing")
            pw.save()
        except DataError:
            messagetiming = "Ошибка ввода срока приема заявок"
            ProgramWork.objects.filter(program_name=pw.program_name).delete()
            return render(request, 'mainpage/addprogram.html',
                          {'username': request.session['username'],
                           'messagename': messagename, 'program_name': request.POST.get("name"),
                           'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming,
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_paying = request.POST.get("paying")
            pw.save()
        except DataError:
            messagepaying = "Ошибка ввода оплаты"
            ProgramWork.objects.filter(program_name=pw.program_name).delete()
            return render(request, 'mainpage/addprogram.html',
                          {'username': request.session['username'],
                           'messagename': messagename, 'program_name': request.POST.get("name"),
                           'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying})
        else:
            latest_program_list = ProgramWork.objects.all()
            return render(request, 'mainpage/index.html',
                          {'latest_program_list': latest_program_list,
                           'username': request.session['username'], 'status': request.session['status']})
    else:
        return render(request, 'mainpage/addprogram.html')


def showedit(request, program_id):
    pw = get_object_or_404(ProgramWork, pk=program_id)
    return render(request, 'mainpage/editprogram.html', {'username': request.session['username'],
                                                         'program_id': program_id, 'program_name': pw.program_name,
                                                         'program_picture': pw.program_picture,
                                                         'program_describe': pw.program_describe,
                                                         'program_during': pw.program_during,
                                                         'program_employment': pw.program_employment,
                                                         'program_direction': pw.program_direction,
                                                         'program_requirement': pw.program_requirement,
                                                         'program_contact': pw.program_contact,
                                                         'program_timing': pw.program_timing,
                                                         'program_paying': pw.program_paying})


@csrf_exempt
def edit(request, program_id):
    messagename = ''
    messagepicture = ''
    messagedescribe = ''
    messageduring = ''
    messageemployment = ''
    messagedirection = ''
    messagerequirement = ''
    messagecontact = ''
    messagepaying = ''
    messagetiming = ''
    pw = get_object_or_404(ProgramWork, pk=program_id)
    if request.method == 'POST':
        try:
            pw.program_name = request.POST.get("name")
            pw.save()
        except DataError:
            messagename = "Ошибка ввода названия"
            return render(request, 'mainpage/editprogram.html',
                          {'username': request.session['username'],
                           'program_id': program_id, 'messagename': messagename, 'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        if request.FILES.get("picture"):
            pw.program_picture.delete()
            pw.program_picture = request.FILES.get("picture")
            picture = str(pw.program_picture).lower().split('.')
            typepicture = picture[-1]
            if typepicture == "jpg" or typepicture == "png" or typepicture == "jpeg":
                pw.save()
            else:
                messagepicture = "Неверный формат изображения"
                return render(request, 'mainpage/editprogram.html',
                              {'username': request.session['username'],
                               'program_id': program_id, 'messagename': messagename,
                               'program_name': request.POST.get("name"), 'messagepicture': messagepicture,
                               'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                               'messageduring': messageduring, 'program_during': request.POST.get("during"),
                               'messageemployment': messageemployment,
                               'program_employment': request.POST.get("employment"),
                               'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                               'messagerequirement': messagerequirement,
                               'program_requirement': request.POST.get("requirement"),
                               'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                               'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                               'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_describe = request.POST.get("describe")
            pw.save()
        except DataError:
            messagedescribe = "Ошибка ввода описания"
            return render(request, 'mainpage/editprogram.html',
                          {'username': request.session['username'],
                           'program_id': program_id, 'messagename': messagename, 'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_name': request.POST.get("name"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_during = request.POST.get("during")
            pw.save()
        except DataError:
            messageduring = "Ошибка ввода продолжительности"
            return render(request, 'mainpage/editprogram.html',
                          {'username': request.session['username'],
                           'program_id': program_id, 'messagename': messagename, 'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_name': request.POST.get("name"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_employment = request.POST.get("employment")
            pw.save()
        except DataError:
            messageemployment = "Ошибка ввода типа занятости"
            return render(request, 'mainpage/editprogram.html',
                          {'username': request.session['username'],
                           'program_id': program_id, 'messagename': messagename, 'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_name': request.POST.get("name"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_direction = request.POST.get("direction")
            pw.save()
        except DataError:
            messagedirection = "Ошибка ввода направлений"
            return render(request, 'mainpage/editprogram.html',
                          {'username': request.session['username'],
                           'program_id': program_id, 'messagename': messagename, 'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_name': request.POST.get("name"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_requirement = request.POST.get("requirement")
            pw.save()
        except DataError:
            messagerequirement = "Ошибка ввода требований"
            return render(request, 'mainpage/editprogram.html',
                          {'username': request.session['username'],
                           'program_id': program_id, 'messagename': messagename, 'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_name': request.POST.get("name"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_contact = request.POST.get("contact")
            pw.save()
        except DataError:
            messagecontact = "Ошибка ввода контактов"
            return render(request, 'mainpage/editprogram.html',
                          {'username': request.session['username'],
                           'program_id': program_id, 'messagename': messagename, 'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_name': request.POST.get("name"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_timing = request.POST.get("timing")
            pw.save()
        except DataError:
            messagetiming = "Ошибка ввода срока приема заявок"
            return render(request, 'mainpage/editprogram.html',
                          {'username': request.session['username'],
                           'program_id': program_id, 'messagename': messagename, 'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_name': request.POST.get("name"),
                           'messagepaying': messagepaying, 'program_paying': request.POST.get("paying")})
        try:
            pw.program_paying = request.POST.get("paying")
            pw.save()
        except DataError:
            messagepaying = "Ошибка ввода типа оплаты"
            return render(request, 'mainpage/editprogram.html',
                          {'username': request.session['username'],
                           'program_id': program_id, 'messagename': messagename, 'messagepicture': messagepicture,
                           'messagedescribe': messagedescribe, 'program_describe': request.POST.get("describe"),
                           'messageduring': messageduring, 'program_during': request.POST.get("during"),
                           'messageemployment': messageemployment, 'program_employment': request.POST.get("employment"),
                           'messagedirection': messagedirection, 'program_direction': request.POST.get("direction"),
                           'messagerequirement': messagerequirement,
                           'program_requirement': request.POST.get("requirement"),
                           'messagecontact': messagecontact, 'program_contact': request.POST.get("contact"),
                           'messagetiming': messagetiming, 'program_timing': request.POST.get("timing"),
                           'messagepaying': messagepaying, 'program_name': request.POST.get("name")})
        latest_program_list = ProgramWork.objects.all()
        return render(request, 'mainpage/index.html', {'latest_program_list': latest_program_list,
                                                       'username': request.session['username'],
                                                       'status': request.session['status']})
    else:
        return render(request, 'mainpage/editprogram.html', {'username': request.session['username'],
                                                             'program_id': program_id, 'program_name': pw.program_name,
                                                             'program_picture': pw.program_picture,
                                                             'program_describe': pw.program_describe,
                                                             'program_during': pw.program_during,
                                                             'program_employment': pw.program_employment,
                                                             'program_direction': pw.program_direction,
                                                             'program_requirement': pw.program_requirement,
                                                             'program_contact': pw.program_contact,
                                                             'program_timing': pw.program_timing,
                                                             'program_paying': pw.program_paying})


def delete(request, program_id):
    pw = get_object_or_404(ProgramWork, pk=program_id)
    pw.program_picture.delete()
    pw.delete()
    latest_program_list = ProgramWork.objects.all()
    return render(request, 'mainpage/index.html', {'latest_program_list': latest_program_list,
                                                   'username': request.session['username'],
                                                   'status': request.session['status']})


def showfav(request, user_id):
    favours_list_program = Favorites.objects.filter(user_id=user_id)
    latest_program_list = []
    for f in favours_list_program:
        latest_program_list += ProgramWork.objects.all().filter(id=f.program_id)
    return render(request, 'mainpage/showfav.html',
                  {'latest_program_list': latest_program_list, 'username': request.session['username'],
                   'status': request.session['status'], 'user_id': request.session['user_id']})


def addfav(request, program_id, user_id):
    latest_program_list = ProgramWork.objects.all()
    favorites = Favorites.objects.filter(program_id=program_id, user_id=user_id)
    if len(favorites) == 0:
        favorite = Favorites()
        favorite.program_id = program_id
        favorite.user_id = user_id
        favorite.save()
    favours_program_list = list(Favorites.objects.all().filter(user_id=user_id).values_list('program_id', flat=True))
    return redirect('/mainpage/filtr',
                    {'username': request.session['username'], 'status': request.session['status'],
                     'user_id': request.session['user_id'], 'latest_program_list': latest_program_list,
                     'favours_program_list': favours_program_list})


def deletefav(request, program_id, user_id):
    latest_program_list = ProgramWork.objects.all()
    favorite = Favorites.objects.filter(program_id=program_id, user_id=user_id)
    if len(favorite) != 0:
        favorite.delete()
    favours_program_list = list(Favorites.objects.all().filter(user_id=user_id).values_list('program_id', flat=True))
    return redirect('/mainpage/filtr',
                    {'username': request.session['username'], 'status': request.session['status'],
                     'user_id': request.session['user_id'], 'latest_program_list': latest_program_list,
                     'favours_program_list': favours_program_list})


@csrf_exempt
def report(request):
    if request.method == 'POST':
        if len(request.POST['fio']) > 50:
            messagefio = "Ошибка ввода ФИО"
            return render(request, 'mainpage/report.html', {'messagefio': messagefio, 'fio': request.POST['fio'],
                                                            'username': request.session['username'], 'status': request.session['status']})
        if re.search(r"^[А-ЯЁа-яё\s]+$", request.POST['fio']):
            doc = DocxTemplate("shablon.docx")
            favouriteprograms = ProgramWork.objects.all()
            for program in favouriteprograms:
                count_favour = Favorites.objects.all().filter(program_id=program.id).count()
                program.program_count_favourite = count_favour
                program.save()
            favouriteprograms = ProgramWork.objects.all().order_by('program_count_favourite').reverse()
            context = {'FIO': request.POST['fio'],
                           'DAY': datetime.now().day, 'MONTH': datetime.now().month,
                           'YEAR': datetime.now().year, 'COUNT_PROGRAMS': ProgramWork.objects.all().count(),
                           'programs': favouriteprograms}
            doc.render(context)
            doc.save(str(datetime.now().date())+str(datetime.now().hour)+str(datetime.now().minute)+".docх")
            messagesuccess = 'Отчет ' + str(datetime.now().date())+str(datetime.now().hour)+str(datetime.now().minute)+".docх" + ' успешно создан'
            return render(request, 'mainpage/report.html', {'messagesuccess': messagesuccess, 'username': request.session['username'],
                                                            'status': request.session['status']})
        else:
            messagefio = "Ошибка ввода ФИО"
            return render(request, 'mainpage/report.html', {'messagefio': messagefio, 'fio': request.POST['fio'],
                                                            'username': request.session['username'], 'status': request.session['status']})
    else:
        return render(request, 'mainpage/report.html', {'username': request.session['username'], 'status': request.session['status']})
