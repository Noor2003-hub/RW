import os
import random
import cs50
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session,url_for, jsonify
from flask_session import Session
from werkzeug.utils import secure_filename
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import display_age, div,filter_data,is_english_letters
from collections import defaultdict
from PIL import Image, UnidentifiedImageError
import numpy as np
from difflib import SequenceMatcher
import json
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import os
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import re
from cryptography.fernet import Fernet
from rapidfuzz import fuzz

MAX_FILE_SIZE = 2 * 1024 * 1024
#openai.api_key = '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'
# Configure application
app = Flask(__name__)
# Configure mail settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'parent.guide.4u@gmail.com'
app.config['MAIL_PASSWORD'] = 'xoxy lyxt dyoc rwzq'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

# Initialize the URL serializer
app.config['SECRET_KEY'] = "9a12b12c5d76f47a5e3d4f2877b2c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b4"

if not app.config['SECRET_KEY']:
    raise ValueError("No SECRET_KEY set for Flask application")

# Initialize the URLSafeTimedSerializer with the secret key
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

with open('cards.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")
db.execute("PRAGMA foreign_keys = ON;")

from cryptography.fernet import Fernet
import base64
# Load your key from a secure place (environment variable or config)

ENCRYPTION_KEY = 'EE_TQZC1dolC7MvOufqONuIBscclbe8FuKJTQ6hcGPw='
cipher_suite = Fernet(ENCRYPTION_KEY)

# Encrypt data
'''def is_parent():
    if not session['user_type']=='p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect('/')
def is_admin():
    if not session['user_type']=='a':
        flash('هذه الصفحة فقط للمسوؤلين')
        return redirect('/')
def is_specialist():
    if not session['user_type']=='s':
        flash('هذه الصفحة فقط للأخصائين')
        return redirect('/')
def is_specialist_or_parent():
    if not (session['user_type']=='s' or session['user_type']=='p'):
        flash('هذه الصفحة فقط لاولياء الامور و الاخصائين')
        return redirect('/login')'''
def find_home():
    if not session:
        return '/'
    else:
        if session['user_type']=='p':
            return '/home'
        elif session['user_type']=='s':
            return '/recent_chats'
        else:
            return '/admin'
def encrypt_message(data):
    encrypted_data = cipher_suite.encrypt(data.encode())
    # Convert encrypted bytes to base64-encoded string for storage
    return base64.urlsafe_b64encode(encrypted_data).decode()

def decrypt_message(encrypted_data):
    # Convert base64-encoded string back to encrypted bytes
    encrypted_data = base64.urlsafe_b64decode(encrypted_data.encode())
    return cipher_suite.decrypt(encrypted_data).decode()
def process_image(file, folder):
    try:
        img = Image.open(file)
        img.verify()  # Verify if the file is a valid image
        img = Image.open(file)  # Re-open for further operations
        img.thumbnail((800, 800))  # Resize to a max of 800x800 pixels

        # Force filename to be .jpg
        filename = secure_filename(os.path.splitext(file.filename)[0] + '.jpg')
        file_path = os.path.join(folder, filename)

        # Convert to RGB to ensure compatibility with JPEG and save
        img.convert('RGB').save(file_path, format='JPEG')

        return file_path
    except UnidentifiedImageError:
        return None

@app.route('/assess_tut', methods=['GET', 'POST'])
def assess_tut():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    return render_template('assess_tut.html')


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if not (session['user_type'] == 's' or session['user_type'] == 'p'):
        flash('هذه الصفحة فقط لاولياء الامور و الاخصائين')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    if session['user_type'] == 'p':
        if request.method == 'POST':
            username = request.form.get('username').lower()
            email = request.form.get('email')
            child_name = request.form.get('child_name')
            child_img = request.files.get('child_img')
            emails = db.execute('select email from users where not id=?',session['user_id'])
            usernames = db.execute('select username from users where not id=?',session['user_id'])
            user = db.execute('select * from users where id=?', session['user_id'])[0]
            child = db.execute('select * from children where user_id=?', session['user_id'])[0]
            for e in emails:
                if e['email']==email:
                    flash('البريد الإلكتروني موجود بالفعل, اختر عنوان بريد اخر')
                    return render_template('settings.html', user=user, child=child)
            print(emails,usernames)
            for u in usernames:
                if u['username']==username:
                    flash('اسم المستخدم موجود بالفعل, اختر اسم مستخدم اخر')
                    return render_template('settings.html', user=user, child=child)

            db.execute('update users set username=?, email=? where id=?', username, email, session['user_id'])
            current_photo_path = db.execute('select * from children where user_id=?', session['user_id'])[0]['photo_path']
            if child_img and child_img.filename != '':
                try:
                    img = Image.open(child_img)
                    img.verify()
                    img = Image.open(child_img)
                except (IOError, SyntaxError):
                    flash("الصورة غير صالحة. يرجى تحميل صورة صالحة.")
                    return redirect('/settings')
                if current_photo_path and os.path.exists(current_photo_path) and 'defult' not in current_photo_path:
                    try:
                        os.remove(current_photo_path)
                    except:
                        print('cant remove pic')
                filename = secure_filename(os.path.splitext(child_img.filename)[0] + '.jpg')
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                img.convert("RGB").save(file_path, format='JPEG')
                resized_path = file_path
            else:
                resized_path = current_photo_path

            db.execute('UPDATE children SET name = ?, photo_path = ? WHERE user_id = ?', child_name, resized_path, session['user_id'])
            flash('تم التحديث بنجاح')
            return redirect(url_for('settings'))
        user = db.execute('select * from users where id=?', session['user_id'])[0]
        child = db.execute('select * from children where user_id=?', session['user_id'])[0]
        return render_template('settings.html', user=user, child=child)
    else:
        if request.method == 'POST':
            username = request.form.get('username').lower()
            email = request.form.get('email')
            name = request.form.get('name')
            spec = request.form.get('spec')
            dob = request.form.get('dob')
            year = request.form.get('date_of_grad')
            desc = request.form.get('desc')
            img = request.files.get('img')
            current_photo_path = db.execute('select * from specialist where id=?', session['user_id'])[0]['img']
            imgg=img
            if imgg and imgg.filename != '':
                try:
                    img = Image.open(imgg)
                    img.verify()
                    img = Image.open(imgg)
                except (IOError, SyntaxError):
                    flash("الصورة غير صالحة. يرجى تحميل صورة صالحة.")
                    return redirect('/settings')
                if current_photo_path and os.path.exists(current_photo_path) and 'defult' not in current_photo_path:
                    try:
                        os.remove(current_photo_path)
                    except:
                        print('cant remove pic')
                filename = secure_filename(os.path.splitext(imgg.filename)[0] + '.jpg')
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                img.convert("RGB").save(file_path, format='JPEG')
                resized_path = file_path
            else:
                resized_path = current_photo_path
            db.execute('UPDATE specialist SET grad_year=?, dob=?, desc=?, spec=?, email=?, username=?, name=?, img=? WHERE id=?', year, dob, desc, spec, email, username, name, resized_path, session['user_id'])
            flash('تم التحديث بنجاح')
            return redirect(url_for('settings'))
        user = db.execute('select * from specialist where id=?', session['user_id'])[0]
        now = datetime.now().year
        return render_template('settings.html', user=user, now=now)


@app.route('/approve', methods=['GET', 'POST'])
def approve():
    if not session['user_type'] == 'a':
        flash('هذه الصفحة فقط للمسوؤلين')
        return redirect(find_home())
    id=request.form.get('id')
    db.execute('update specialist set approved=1 where id=?',id)
    db.execute('update specialist set approve_date=? where id=?',datetime.now().date(), id)
    user=db.execute('select * from specialist where id=?',id)[0]
    send_email3(user)
    flash('تم قبول الطلب')
    return redirect('/admin')

@app.route('/cancle', methods=['GET', 'POST'])
def cancle():
    if not session['user_type'] == 'a':
        flash('هذه الصفحة فقط للمسوؤلين')
        return redirect(find_home())
    id=request.form.get('id')
    approved=db.execute('select approved from specialist where id=?',id)
    img=db.execute('select img from specialist where id=?',id)[0]['img']
    cer = db.execute('select certificate from specialist where id=?', id)[0]['certificate']
    if img!='static/unknown.png':
        try:
            os.remove(img)
        except:
            print('cant remove pic')
    try:
        os.remove(cer)
    except:
        print('cant remove pic')
    print(id,db.execute('select * from specialist '))
    print(id, db.execute('select * from specialist where id=?',id))
    db.execute('DELETE FROM messages WHERE specialist_id = ?', (id,))
    db.execute('DELETE FROM specialist WHERE id = ?', (id,))
    if session.get('user_id') == int(id) and session.get('user_type') != 'a':
        session.clear()
        flash('تم حذف حسابك. تم تسجيل خروجك.')
        return redirect('/login')
    if approved==0:
        flash('تم رفض الطلب')
        return redirect('/admin')
    else:
        flash('تم ازالة الحساب')
        return redirect('/approved')


@app.route('/register2', methods=['GET', 'POST'])
def register2():
    if request.method == "POST":
        print(request.files)

        username = request.form.get("username")
        name = request.form.get("name")
        date_of_birth = request.form.get("date_of_birth")
        date_of_grad = request.form.get("date_of_grad")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        spec=request.form.get("spec")
        desc = request.form.get("desc")
        if not is_english_letters(username):
            flash("اسم المستخدم يجب ان يكون بالحروف الانجليزية")
            return redirect('/register2')
        if not username or not password or not confirmation or not name or not date_of_birth or not date_of_grad or not email:
            flash("الرجاء اكمال الفراغات")
            return redirect("/register2")
        if db.execute("SELECT * FROM specialist WHERE username = ?", username):
            flash("اسم المستخدم موجود بالفعل. اختر اسم اخر.")
            return redirect("/register2")
        if password != confirmation:
            flash("كلمة المرور غير مطابقة.")
            return redirect("/register2")
        if len(password) < 5:
            flash("يجب أن تكون كلمة المرور أطول من 5 أحرف")
            return redirect("/register2")
        emails = db.execute('select email from specialist')
        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_pattern, email):
            flash('الرجاء إدخال عنوان بريد إلكتروني صحيح')
            return redirect("/register2")
        for e in emails:
            if e['email'] == email:
                flash('هذا البريد الكتروني مستخدم مسبقا. الرجاء إختيار عنوان بريد الكتروني اخر')
                return redirect("/register2")
        has_num = any(char.isdigit() for char in password)

        if not has_num:
            flash("يجب أن تحتوي كلمة المرور على رقم واحد على الأقل.")
            return redirect("/register2")

        if 'img' in request.files and request.files['img'].filename != '':
            file = request.files['img']
            resized_path = process_image(file, app.config['UPLOAD_FOLDER'])

            if resized_path is None:
                flash("الصورة الأولى ليست صورة صالحة.")
                return redirect("/register2")
        else:
            flash('الرجاء ارفاق الشهادة')
            return redirect('/register2')

        # Processing second image (img2)
        if 'img2' in request.files and request.files['img2'].filename != '':
            file2 = request.files['img2']
            resized_path2 = process_image(file2, app.config['UPLOAD_FOLDER'])

            if resized_path2 is None:
                flash("الصورة الثانية ليست صورة صالحة.")
                return redirect('/register2')
        else:
            resized_path2 = 'static/unknown.png'
        db.execute('insert into specialist (username, hash,email,name,spec,dob,grad_year,desc,certificate,img,request_date) values (?,?,?,?,?,?,?,?,?,?,?)',username.lower(),generate_password_hash(password),email,name,spec,datetime.strptime(date_of_birth, '%Y-%m-%d').date(),date_of_grad,desc,resized_path,resized_path2,datetime.now().date())
        flash('تم إنشاء حساب بنجاح. الرجاء انتظار بريد الكتروني بالموافقة للتمكن من استخدام حساب الاخصائي')
        return redirect("/")
    else:
        now=datetime.now().year
        return render_template("register2.html",now=now)




@app.route("/recent_chats")
def recent_chats():
    if not (session['user_type'] == 's' or session['user_type'] == 'p'):
        flash('هذه الصفحة فقط لاولياء الامور و الاخصائين')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    user_type = session['user_type']  # Check if the user is a parent or a specialist

    if user_type == "p":
        # For users, retrieve recent chats where they are involved along with specialist's image
        recent_chats = db.execute("""
            SELECT s.id AS recipient_id, s.name AS recipient_name, s.img AS recipient_image, m.content, m.timestamp, m.sender
            FROM messages m
            JOIN specialist s ON m.specialist_id = s.id
            WHERE m.timestamp = (
                SELECT MAX(m2.timestamp)
                FROM messages m2
                WHERE m2.specialist_id = m.specialist_id
                  AND m2.user_id = m.user_id
            ) AND m.user_id = ?
            ORDER BY m.timestamp DESC
        """, session["user_id"])
        user = db.execute('select * from users where id=?', session['user_id'])



    else:

        # For specialists, retrieve recent chats where they are involved

        recent_chats = db.execute("""
                SELECT u.id AS recipient_id, u.username AS recipient_name, 
                       m.content, m.timestamp, m.sender
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.specialist_id = ?
                  AND m.timestamp = (
                      SELECT MAX(m2.timestamp)
                      FROM messages m2
                      WHERE m2.user_id = m.user_id
                        AND m2.specialist_id = m.specialist_id
                  )
                ORDER BY m.timestamp DESC
            """, session["user_id"])
        user = db.execute('select * from specialist where id=?', session['user_id'])
        for i in recent_chats:
            i['recipient_name']='User_'+str(i['recipient_id'])
            i['recipient_image']='static/defult/unknown.jpg'
        print(recent_chats)
    #print(recent_chats)
    now = datetime.now().year
    print(session['user_type'])
    #print( db.execute('select * from specialist where id=?', session['user_id']))
    #print(session['user_id'],user)
    user=user[0]
    for c in recent_chats:
        c['content']=decrypt_message(c['content'])
    return render_template("recent_chats.html", recent_chats=recent_chats, user_type=user_type,user=user,now=now)




@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    l = db.execute('select * from specialist where approved=1')
    now=datetime.now().year
    for i in l:
        #print(i)
        i['grad_year']=now-i['grad_year']
        dob=i['dob']
        i['dob']=calculate_age2(dob)
        print(i['dob'])
    return render_template('contact.html',l=l)

def send_email(to, reset_url,user):
    msg = Message('إعادة تعيين كلمة المرور الخاصة بك - الإجراء مطلوب', sender='your-email@example.com', recipients=[to])
    name=user[0]['username']
    msg.body = f'''{name}،

لقد طلبت مؤخرًا إعادة تعيين كلمة المرور الخاصة بك لخدمتنا. انقر على الرابط أدناه لإعادة تعيين كلمة المرور الخاصة بك بشكل آمن:

{reset_url}

إذا لم تطلب إعادة تعيين كلمة المرور هذه، فيرجى تجاهل هذا البريد الإلكتروني. سيظل حسابك آمنًا.

شكرًا لك،
ParentGuide '''
    try:
        mail.send(msg)
    except:
        print('cant send msg')
def send_email2(user):
    child=db.execute('select * from children where user_id=?',session['user_id'])[0]
    child_name=child['name']
    child_age=display_age(child['dob'])
    msg = Message(f'تهانينا بمناسبة عيد ميلاد {child_name} وافتتاح فئة عمرية جديدة! 🥳🎊', sender='your-email@example.com', recipients=[user['email']])
    name=user['username']
    msg.body = f'''مرحبًا {name}،

. يسرنا أن نتقدم بأحر التهاني وأطيب التبريكات بمناسبة عيد ميلاد طفلكم العزيز وإتمامه {display_age(child['dob'])} .نتمنى له دوام الصحة والسعادة.

تأكد من ان تتطلع على الفئة العمرية الجديدة عبر تطبيقنا، تتضمن مجموعة من المهارات والأنشطة الجديدة المصممة خصيصًا لتتناسب مع احتياجات وتطور طفلكم في هذه المرحلة. الآن، يمكن لطفلكم الاستفادة من المهارات الجديدة التي يمكنه تعلمها وتطويرها، مما سيساعده على النمو والتطور بشكل سليم.

نحن متحمسون لرؤية طفلكم وهو يستمتع بتجربة هذه المهارات الجديدة، ونأمل أن تكونوا مستعدين للانضمام إلينا في هذا المشوار الممتع والمفيد.

لمزيد من التفاصيل حول الفئة الجديدة والمهارات المتاحة، يمكنكم زيارة التطبيق والاطلاع على القسم الجديد المخصص لعمر وإتمامه {child_age}. كما يسعدنا تلقي استفساراتكم واقتراحاتكم في أي وقت.

شكرًا لثقتكم المستمرة بنا ونتطلع إلى مزيد من النجاحات معكم ومع أطفالكم الأعزاء.

مع أطيب التحيات،
ParentGuide '''
    try:
        mail.send(msg)
    except:
        print('cant send msg')
def send_email3(user):
    msg = Message(f'تم قبول الانضمام الى موقعنا', sender='your-email@example.com', recipients=[user['email']])
    user_name=user['name']
    login_link=url_for('login', _external=True)
    index_link=url_for('index', _external=True)
    msg.body = f'''مرحبًا {user_name}،
تم قبولك في طاقم عمل موقعنا parentguide

يمكنك الان تسجيل الدخول من هنا:
{login_link}

وسوف تتمكن من استخدام الموقع و الرد على أسئلة المستخدمين فيما يتعلق بالأطفال

أو يمكنك زيارة موقعنا:
{index_link}

مع تحيات فريق ParentGuide
'''
    try:
        mail.send(msg)
    except:
        print('cant send msg')

def send_email4(specialist):
    user = db.execute('SELECT * FROM users WHERE id=?', session['user_id'])[0]
    msg = Message(f' لديك رسالة جديدة 📩', sender='your-email@example.com', recipients=[specialist['email']])
    specialist_name=specialist['name']
    linkk=url_for('chat', recipient_id=user['id'], _external=True)
    msg.body = f'''مرحبًا {specialist_name}،

وصلتك رسالة جديدة من احد مستخدمين موقعنا PartenGuide

الرجاء الدخول للرد على الرسالة: {linkk}

مع تحيات فريق ParentGuide
'''
    try:
        mail.send(msg)
    except:
        print('cant send msg')
def send_email5(user):
    specialist = db.execute('SELECT * FROM specialist WHERE id=?', session['user_id'])[0]
    msg = Message(f' لديك رسالة جديدة 📩', sender='your-email@example.com', recipients=[user['email']])
    name1=user['username']
    name2=specialist['name']
    linkk=url_for('chat', recipient_id=specialist['id'], _external=True)
    msg.body = f'''مرحبًا {name1}،

وصلتك رسالة جديدة من {name2}

الرجاء الدخول للاطلاع على الرسالة: {linkk}

مع تحيات فريق ParentGuide
'''
    try:
        mail.send(msg)
    except:
        print('cant send msg')


@app.route("/chat/<int:recipient_id>", methods=["GET", "POST"])
def chat(recipient_id):
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    user_type = session.get('user_type')
    if user_type == "p":
        recipient = db.execute("SELECT * FROM specialist WHERE id = ?", recipient_id)[0]
        sender = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])[0]
    else:
        recipient = db.execute("SELECT * FROM users WHERE id = ?", recipient_id)[0]
        sender = db.execute("SELECT * FROM specialist WHERE id = ?", session['user_id'])[0]
    if request.method == "POST":
        message = request.form.get("message")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        if user_type == 'p':
            db.execute("INSERT INTO messages (user_id, specialist_id, content, timestamp, sender) VALUES (?, ?, ?, ?, ?)",
                session["user_id"], recipient_id, encrypt_message(message), timestamp, 1)
            send_email4(recipient)
        else:
            db.execute("INSERT INTO messages (user_id, specialist_id, content, timestamp, sender) VALUES (?, ?, ?, ?, ?)",
                recipient_id, session["user_id"], encrypt_message(message), timestamp, 0)
            send_email5(recipient)
        if request.is_xhr:
            new_message = f"""
            <div class='my-message'>
                <span class='message-content'>{message}</span>
                <span class='timestamp-left'>{timestamp}</span>
            </div>
            """
            return new_message
        return redirect(url_for('chat', recipient_id=recipient_id))
    messages = db.execute(
        "SELECT * FROM messages WHERE (user_id = ? AND specialist_id = ?) OR (user_id = ? AND specialist_id = ?)",
        session["user_id"], recipient_id, recipient_id, session["user_id"]
    )
    if messages:
        last_message = messages[-1]
        if (user_type == 'p' and last_message['sender'] == 0) or (user_type == 's' and last_message['sender'] == 1):
            db.execute("UPDATE messages SET seen = 1 WHERE id = ? AND seen = 0", last_message['id'])
        sender_id = last_message['sender'] if user_type == 'p' else 1 - last_message['sender']
        db.execute("UPDATE messages SET seen = 1 WHERE user_id = ? AND specialist_id = ? AND seen = 0",
                   sender_id, recipient_id)

        seen = last_message['seen'] if (messages[-1]['sender'] == 0 and session['user_type'] == 's') or \
                                       (messages[-1]['sender'] == 1 and session['user_type'] == 'p') else False
    else:
        seen = False
    for message in messages:
        message['content'] = decrypt_message(message['content'])
    return render_template("chat.html", recipient=recipient, messages=messages, user_type=user_type, seen=seen,
                           last=messages[-1] if messages else None)


@app.route('/view_development')
def view_development():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_plan():
        flash('هذا المحتوى غير مسموح للوصل له قبل الانتهاء من تقييم الطفل. الرجاء إكمال تقييم مهارات الطفل')
        return find_assess()
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    user_id = session.get('user_id')
    child = db.execute('SELECT * FROM children WHERE user_id=?', (user_id,))[0]
    age = calculate_age2(child['dob'])
    disability = child['disability']
    categories = {
        'motion': 'الحركة',
        'language': 'اللغة',
        'cognitive': 'الإدراك',
        'social': 'المخالطة الاجتماعية',
        'self_help': 'المساعدة الذاتية'
    }
    risk = []
    for category, arabic_name in categories.items():
        category_age = db.execute(f'SELECT {category}_age FROM children WHERE user_id=?', (user_id,))[0][f'{category}_age']
        if age - int(category_age) >= 2:
            risk.append(arabic_name)
    categories_order = ['اللغة', 'الإدراك', 'الحركة', 'المساعدة الذاتية', 'المخالطة الاجتماعية']
    data = {cat: [] for cat in categories_order}
    history = db.execute('SELECT * FROM development_history WHERE user_id=? ORDER BY time ASC', (user_id,))
    for record in history:
        category = categories.get(record['category'], record['category'])
        record_time = datetime.strptime(record['time'], '%Y-%m-%d %H:%M:%S')
        if category in data:
            data[category].append({
                'time': record_time,
                'percentage': record['percentage']
            })
    start_date = min(record['time'].date() for records in data.values() for record in records)
    end_date = datetime.now().date()
    dates = [start_date + timedelta(days=x) for x in range((end_date - start_date).days + 1)]
    organized_data = {}
    labels = set()
    for category, records in data.items():
        organized_data[category] = []
        date_to_percentage = {record['time'].date(): record['percentage'] for record in records}
        last_percentage = None
        for date in dates:
            labels.add(date.strftime('%Y-%m-%d'))
            percentage = date_to_percentage.get(date, last_percentage)
            organized_data[category].append({
                'time': date.strftime('%Y-%m-%d'),
                'percentage': percentage
            })
            last_percentage = percentage
    time_range = request.args.get('time_range', 'week')
    organized_data = filter_data(time_range, organized_data)
    colors = [['rgb(255, 99, 132)', 'rgba(255, 99, 132, 0.5)'],['rgb(255, 159, 64)', 'rgba(255, 159, 64, 0.5)'], ['rgb(75, 192, 192)', 'rgba(75, 192, 192, 0.5)'], ['rgb(54, 162, 235)', 'rgba(54, 162, 235, 0.5)'], ['rgb(153, 102, 255)', 'rgba(153, 102, 255, 0.5)']]
    zipped_data = [
        [category, color, organized_data[category][-1]['percentage']]
        for category, color in zip(organized_data.keys(), colors)
    ]
    if disability == 0 and risk:
        risk_message = '❗⚠ تم رصد تأخر في مجال: ' + ', '.join(risk)
        risk_message += ', قد يكون مؤشر غير مطمئن. يرجى مراجعة أخصائي في اسرع وقت ممكن للتأكد من حالة طفلك.'
        flash(risk_message)
    motion_age=db.execute('select motion_age from children where user_id=?',session['user_id'])[0]['motion_age']
    social_age=db.execute('select social_age from children where user_id=?',session['user_id'])[0]['social_age']
    cognitive_age=db.execute('select cognitive_age from children where user_id=?',session['user_id'])[0]['cognitive_age']
    self_help_age=db.execute('select self_help_age from children where user_id=?',session['user_id'])[0]['self_help_age']
    language_age=db.execute('select language_age from children where user_id=?',session['user_id'])[0]['language_age']
    ages=[self_help_age,language_age,social_age,cognitive_age,motion_age]
    return render_template('view_development.html',ages=ages,time_range=time_range, zipped_data=zipped_data, dataa=organized_data, labelz=sorted(labels), colors=colors)





def find_assess():
    motion_json = json.loads(
        db.execute('select motion_json from children where user_id=?', session["user_id"])[0]['motion_json'])
    for item in motion_json:
        if item['scale'] == -1:
            return redirect('/assess_motion')
    language_json = json.loads(
        db.execute('select language_json from children where user_id=?', session["user_id"])[0]['language_json'])
    for item in language_json:
        if item['scale'] == -1:
            # print(item)
            return redirect('/assess_lang')
    social_json = json.loads(
        db.execute('select social_json from children where user_id=?', session["user_id"])[0]['social_json'])
    for item in social_json:
        if item['scale'] == -1:
            return redirect('/assess_social')
    cognitive_json = json.loads(
        db.execute('select cognitive_json from children where user_id=?', session["user_id"])[0]['cognitive_json'])
    for item in cognitive_json:
        if item['scale'] == -1:
            return redirect('/assess_cognitive')
    self_help_json = json.loads(
        db.execute('select self_help_json from children where user_id=?', session["user_id"])[0]['self_help_json'])
    for item in self_help_json:
        if item['scale'] == -1:
            return redirect('/assess_self_help')
    child = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]
    dob = child['dob']
    disability = child['disability']
    child_age = calculate_age2(dob)
    plan = json.loads(
        db.execute('select development_plan from children where user_id=?', (session['user_id']))[0][
            'development_plan'])
    jsons={'الحركة':motion_json,'اللغة':language_json,'الإدراك':cognitive_json,'المساعدة الذاتية':self_help_json,'المخالطة الاجتماعية':social_json}
    #print(jsons)
    #print('ii::',plan)
    if child_age>=6:
        child_age=5
    r=str(child_age)+' – '+str(child_age+1)
    #print(range)
    ranges=[]
    x=0
    print(plan.keys(),r,)
    print(r not in plan.keys(),r not in plan.keys() and (int(r[0]) < 6))
    while r not in plan.keys() and (int(r[0]) < 6):
        ranges.append(r)
        x+=1
        r=str(child_age-x) + ' – ' + str((child_age + 1)-x)
    print(ranges)
    if ranges:
        flash('تم إضافة فئة عمرية جديدة! عيد ميلاد سعيد 🥳🎊')
        user = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])[0]
        send_email2(user)
    for range in ranges:
        data = load_data()
        for cate in jsons:
            jsonn2 = filter_by_age(data, child_age)[cate]
            for i in jsonn2:
                i['scale']=-2
            jsons[cate] += jsonn2
            if cate=='اللغة':
                db.execute('update children set language_json=? where user_id=?', json.dumps(jsons[cate]), session["user_id"])
            elif cate=='الحركة':
                db.execute('update children set motion_json=? where user_id=?', json.dumps(jsons[cate]), session["user_id"])
            elif cate=='المخالطة الاجتماعية':
                db.execute('update children set social_json=? where user_id=?', json.dumps(jsons[cate]), session["user_id"])
            elif cate=='المساعدة الذاتية':
                db.execute('update children set self_help_json=? where user_id=?', json.dumps(jsons[cate]), session["user_id"])
            elif cate=='الإدراك':
                db.execute('update children set cognitive_json=? where user_id=?', json.dumps(jsons[cate]), session["user_id"])
        

        #print('99::',child_age,plan)
        jsonn2 = filter_by_age(data, child_age)
        plan[range]=jsonn2
        plan=list(set(plan))
        db.execute('update children set(development_plan)=? where user_id=?', json.dumps(plan), session["user_id"])
    return redirect("/home")



# Function to load data from JSON
def load_data():
    try:
        with open('modified_cards.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        return None
def save_data(filename, data):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        print(f"Modified JSON data saved to '{filename}'")
    except Exception as e:
        print(f"Error saving JSON file '{filename}': {e}")

def check_session():
    print(session.get("user_id"))
    if session.get("user_id") is not None:
        return True
    else:
        return False
def check_plan():
    plan=db.execute('select development_plan from children where user_id=?',session['user_id'])[0]['development_plan']
    #print('kk::',plan)
    if plan is not None:
        return True
    else:
        return False
# Function to calculate age from birthdate
def calculate_age2(date_or_age_range):
    if date_or_age_range == 'منذ الولادة – 1':
        return 0
    elif ' – ' in date_or_age_range:
        try:
            age_range = date_or_age_range.split(' – ')
            return int(age_range[0])
        except Exception as e:
            print(f"Error parsing age range '{date_or_age_range}': {e}")
            return None
    else:
        try:
            # Handle the format "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DD"
            if ' ' in date_or_age_range:
                date_of_birth = datetime.strptime(date_or_age_range, "%Y-%m-%d %H:%M:%S")
            else:
                date_of_birth = datetime.strptime(date_or_age_range, "%Y-%m-%d")

            today = datetime.today()
            age = today.year - date_of_birth.year - (
                    (today.month, today.day) < (date_of_birth.month, date_of_birth.day))
            return age
        except ValueError as e:
            print(f"Error calculating age for '{date_or_age_range}': {e}")
            return None

# Function to filter performances by age
def filter_by_age(data, age):
    filtered_data = {}
    for category, performances in data.items():
        #for p in performances:
            #print(p['age'],calculate_age2(p['age']),age)
        filtered_data[category] = [p for p in performances if calculate_age2(p['age']) == age]
    return filtered_data


def create_age_ranges_structure(data, age_ranges):
    age_ranges_data = {
        age_range: {"المساعدة الذاتية": [], "اللغة": [], "المخالطة الاجتماعية": [], "الإدراك": [], "الحركة": []} for
        age_range in age_ranges}

    for category, items in data.items():
        for item in items:
            age = calculate_age2(item['age'])
            if age is not None:
                for age_range in age_ranges:
                    lower, upper = map(int, age_range.split(' – '))
                    if lower <= age < upper:
                        # Check if the item is already in the list
                        if not any(existing_item['title'] == item['title'] for existing_item in age_ranges_data[age_range][category]):
                            age_ranges_data[age_range][category].append(item)
                        break

    return age_ranges_data


def filter_category_by_age(data, age):
    filtered_data = []
    for p in data:
        if calculate_age2(p['age']) == int(age):
            filtered_data.append(p)
    return filtered_data

def ez_update(category,title,scale,comment):
    agee = db.execute('select * from children where user_id=?', session["user_id"])[0][category+'_age']#['motion_age'][0][age_col]
    jsonn = json.loads(
        db.execute('select * from children where user_id=?',session["user_id"])[0][category+'_json'])
    for item in jsonn:
        if item['title'] == title:
            item['scale'] = scale
            item['comment']=comment
            print(f"Updated {category} - {title}: {item}")
            break
    db.execute('update children set ?=? where user_id=?',category+'_json', json.dumps(jsonn), session["user_id"])

    return jsonn,agee


# Check if any skills are missing in the current or previous age ranges
def get_initial_percentage(agee, category):
    jsonn = json.loads(db.execute('select * from children where user_id=?', session["user_id"])[0][category])

    # Check if the child has any skills marked as missing (0 or -2) in their current or previous age ranges
    missing_skills = any(int(skill['scale']) == 0 or int(skill['scale']) == -2 for skill in jsonn)

    # If no skills are missing, return 100%; otherwise, return 0%
    if missing_skills:
        return 0
    else:
        return 100




def ez_submit(category,start,end,filter,substep):
    agee = db.execute('select * from children where user_id=?', session["user_id"])[0][category+'_age']
    jsonn = json.loads(
        db.execute('select * from children where user_id=?', session["user_id"])[0][category+'_json'])
    any_negative = any(int(i['scale']) == -1 for i in jsonn)
    if any_negative:
        flash('يرجى إكمال جميع البيانات')
        for i in jsonn:
            print(i['scale'])
        return render_template(start, data=jsonn, child_age=str(agee), current_step=3,current_substep=substep-1)
    all_zero = all(int(i['scale']) == 0 for i in jsonn)
    if all_zero and agee > 0:
        #print(agee)
        agee -= 1
        data = load_data()
        jsonn2 = filter_by_age(data, agee)[filter]
        '''print('a:',jsonn)
        print('b:',jsonn2)'''
        jsonn += jsonn2
        db.execute('update children set ?=? where user_id=?',category+'_json' ,json.dumps(jsonn), session["user_id"])
        db.execute('update children set ?=? where user_id=?',category+'_age', agee, session["user_id"])
        flash(f'يشير تقييم طفلك إلى أنه قد يستفيد من تقييم الفئة العمرية السابقة. يرجى إكمال القائمة')

        return render_template(start, data=jsonn, child_age=str(agee), current_step=3,current_substep=substep-1)
    else:
        data=load_data()
        filtered_data =[]
        child= db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]
        dob=child['dob']
        child_age=calculate_age2(dob)
        for p in data[filter]:
            if (calculate_age2(p['age']) <agee):
                p['scale']=-2
                p['comment']=''
                filtered_data.append(p)

        print('******',filtered_data)
        jsonn=filtered_data+jsonn
        filtered_data = []
        for p in data[filter]:
            if (agee<calculate_age2(p['age'])<=child_age ):
                p['scale']=-2
                p['comment']=''
                filtered_data.append(p)
        jsonn = jsonn+filtered_data
        db.execute('update children set ?=? where user_id=?',category+'_json', json.dumps(jsonn), session["user_id"])
        if end=='/home':
            dob = db.execute('select dob from children where user_id=?', session["user_id"])[0]['dob']
            motion_json=json.loads(db.execute('select * from children where user_id=?', session["user_id"])[0]['motion_json'])
            language_json = json.loads(db.execute('select * from children where user_id=?', session["user_id"])[0]['language_json'])
            social_json = json.loads(
                db.execute('select * from children where user_id=?', session["user_id"])[0]['social_json'])
            cognitive_json = json.loads(
                db.execute('select * from children where user_id=?', session["user_id"])[0]['cognitive_json'])
            self_help_json = json.loads(
                db.execute('select * from children where user_id=?', session["user_id"])[0]['self_help_json'])
            #print(self_help_json)
            #print('y:',plan)
            data = {"المساعدة الذاتية": self_help_json,'اللغة':language_json,'المخالطة الاجتماعية':social_json,'الإدراك':cognitive_json,'الحركة':motion_json}
            n = calculate_age2(dob)
            disability = child['disability']
            if disability == 1 and n > 6:
                n = 5
            ranges = [f'{n} – {n + 1}']
            for i in range(n):
                n -= 1
                ranges.append(f'{n} – {n + 1}')
            plan = create_age_ranges_structure(data,ranges)
            print('x:',plan)
            db.execute('update children set(development_plan)=? where user_id=?',json.dumps(plan),session["user_id"])

            filtered_performances = []
            dob = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]['dob']
            child_age = calculate_age2(dob)
            for age_range, categories in plan.items():
                for category, performances in categories.items():
                    c, total = 0, 0
                    for performance in performances:
                        scale = performance.get("scale", -1)
                        if scale ==2:
                            performance["category"] = category
                            filtered_performances.append(performance)
                            c+=1
                        total+=1
                    print(total,c,total==c)
                    cat_age=db.execute('select ? from children where user_id=?',category+'_age',session['user_id'])

                    if total==c and not cat_age==child_age:
                        db.execute('insert into development_history (user_id,category,percentage) values (?,?,?) ',session["user_id"],category,100)
            data2 = {"المساعدة الذاتية": 'self_help_json', 'اللغة': 'language_json', 'المخالطة الاجتماعية': 'social_json',
                    'الإدراك': 'cognitive_json', 'الحركة': 'motion_json'}
            # Update the development history with the correct initial percentage
            for cat in data:
                # Check if a record exists for this category
                existing_record = db.execute(
                    'select percentage from development_history where user_id=? and category=?',
                    session["user_id"], cat)

                if not existing_record:
                    # If no record exists, insert the initial percentage (0 or 100 based on missing skills)
                    print(cat,data2[cat])
                    initial_percentage = get_initial_percentage(agee, data2[cat])
                    db.execute('insert into development_history (user_id, category, percentage) values (?, ?, ?)',
                               session["user_id"], cat, initial_percentage)
        return redirect(end)


@app.route('/update', methods=['POST'])
def update():##for activity
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    '''print(4444444444444444444)
    print(request.form)
    print(request.form.get('category'))
    print(request.form['comment'])'''
    category = request.form['category']
    comment = request.form['comment']
    #print('eeeeee:',comment)
    #print(category)
    child_age = request.form['child_age']
    #print(child_age)
    if category=='الإدراك':
        cat='cognitive'
    elif category=='اللغة':
        cat='language'
    elif category=='المساعدة الذاتية':
        cat='self_help'
    elif category=='الحركة':
        cat='motion'
    else:
        cat = 'social'
    dob = db.execute('select * from children where user_id=?', session['user_id'])[0]['dob']

    print(request.form)
    age_range = request.form['age_range']

    if age_range != '0 – 1':
        p2 = str(int(age_range[0]) - 1) + ' – ' + str(int(age_range[4]) - 1)
    else:
        p2 = ''
    if age_range != '5 – 6' and int(age_range[0]) < calculate_age2(dob):
        n = str(int(age_range[0]) + 1) + ' – ' + str(int(age_range[4]) + 1)
    else:
        n = ''
    #print(category)
    plan = json.loads(
        db.execute('select development_plan from children where user_id=?', session["user_id"])[0]['development_plan'])

    title = request.form.get('performance_title')
    if request.form.get('scale'):
        scale = int(request.form.get('scale'))
        #print(scale)
        jsoni,agei = ez_update(cat, title, scale,comment)
        agei=child_age
        #print(plan[agei][category])
        ach = db.execute('select achievements from children where user_id=?', session["user_id"])[0]['achievements']
        if ach is None:
            ach=[]
        else:
            ach=json.loads(ach)
        for p in plan[agei][category]:
            if p['title']==title:
                p['comment'] = comment
                cat_age = db.execute('select * from children where user_id=?', session['user_id'])[0][cat + '_age']
                if p in ach and scale!=2:#p should be removed from ach
                    ach.remove(p)
                    l = []
                    for age_range, categories in plan.items():
                        for categoryy, performances in categories.items():
                            for performance in performances:
                                scalee = performance.get("scale", -1)
                                if scalee in [0, 1]:
                                    performance["category"] = categoryy
                                    print(performance['age'], performance['age'][0], cat_age)
                                    if categoryy == category and int(performance['age'][0]) == int(cat_age-1):
                                        print('found')
                                        l.append(performance)
                    print('l=',l)
                    #print(loveme)
                    '''print(len(filtred_ach) , len(filtered_performances))
                    percentage=div(len(filtred_ach) , len(filtered_performances)+1)
                    db.execute('insert into development_history (user_id,category,percentage) values(?,?,?)',session['user_id'],category,percentage )
                    '''
                    db.execute('update children set(achievements)=? where user_id=?',json.dumps(ach),session['user_id'])
                '''if scale in [0,1]:
                    print( (len(filtred_ach) , len(filtered_performances)+1))
                    percentage = div(len(filtred_ach) , len(filtered_performances)+1)
                    db.execute('insert into development_history (user_id,category,percentage) values(?,?,?)',session['user_id'],category,percentage )'''
                if p['scale'] in [0,1] and scale==2:
                    if p not in ach:#p needs to be added to ach
                        #print('a:',p['scale'] , scale)
                        p['scale'] = scale
                        p['category']=category
                        p['time'] = datetime.now().strftime('%Y-%m-%d')
                        ach.append(p)
                    db.execute('update children set(achievements)=? where user_id=?', json.dumps(ach),
                               session['user_id'])

                    #print(cat_age,'******')
                    l = []
                    for age_range, categories in plan.items():
                        for categoryy, performances in categories.items():
                            for performance in performances:
                                scalee = performance.get("scale", -1)
                                if scalee in [0, 1]:
                                    performance["category"] = categoryy
                                    print(performance['age'],performance['age'][0],cat_age)
                                    if categoryy == category and int(performance['age'][0])==int(cat_age):
                                        print('found')
                                        l.append(performance)
                    dob= db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]['dob']
                    #print(int(cat_age),int(calculate_age2(dob)))
                    if l==[] and int(cat_age)!=int(calculate_age2(dob)):
                        db.execute('update children set (?)=? where user_id=?',cat+'_age',cat_age+1,session['user_id'])






                    #######
                p['scale']=scale
                #print('oo:',scale,p)
        filtered_performances = []
        for age_range, categories in plan.items():
            for categoryy, performances in categories.items():
                for performance in performances:
                    scalee = performance.get("scale", -1)
                    if scalee in [0, 1]:
                        performance["category"] = categoryy
                        if categoryy == category:
                            filtered_performances.append(performance)

        filtred_ach = []
        for i in ach:
            if 'category' in i.keys():
                if i['category'] == category:
                    filtred_ach.append(i)
        '''print('q::::', filtred_ach, filtered_performances)
        print('q//', len(filtred_ach), len(filtered_performances))'''
        percentage = div(len(filtred_ach), len(filtered_performances))
        result=db.execute('select * from development_history where user_id=?',session['user_id'])
        '''print(result)
        print(result[-1])'''
        if result[-1]['user_id']==session['user_id'] and result[-1]['category']==category and result[-1]['percentage']== percentage:
            print('done')
        else:
            db.execute('insert into development_history (user_id,category,percentage) values(?,?,?)',
                   session['user_id'], category, percentage)

        db.execute('update children set(development_plan)=? where user_id=?',json.dumps(plan),session["user_id"])
        flash(f"تم تأكيد {title} بنجاح ", 'success')
        print(n,p)
        return render_template('activity.html',n=n,p=p2, data=plan[agei][category], age_range=str(agei), category=category)
    else:
        flash(f"لم يتم تحديد تقييم للمهارة {title}, الرجاء تحديد تقييم قبل التأكيد", 'success')
        return render_template('activity.html',n=n,p=p2, data=plan[child_age][category], age_range=str(child_age), category=category)



@app.route('/ach', methods=['POST', 'GET'])
def ach():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_plan():
        flash('هذا المحتوى غير مسموح للوصل له قبل الانتهاء من تقييم الطفل. الرجاء إكمال إنشاء الحساب')
        return find_assess()
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    data=db.execute('select achievements from children where user_id=? ',session["user_id"])[0]['achievements']
    if data is not None:
        return render_template('ach.html', data=json.loads(data))
    else:
        return render_template('ach.html', data=data)



@app.route('/update2', methods=['POST'])
def update2():#home
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    conf=False
    # print(4444444444444444444)
    category = request.form['category']
    comment = request.form['comment']
    print('eeeeee:', comment)
    print(category)
    child_age = request.form['child_age']
    # print(child_age)
    if category == 'الإدراك':
        cat = 'cognitive'
    elif category == 'اللغة':
        cat = 'language'
    elif category == 'المساعدة الذاتية':
        cat = 'self_help'
    elif category == 'الحركة':
        cat = 'motion'
    else:
        cat = 'social'

    print(category,child_age)
    plan = json.loads(
        db.execute('select development_plan from children where user_id=?', session["user_id"])[0]['development_plan'])
    child = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]
    #print(filtered_performances)
    ach = child['achievements']
    if ach is not None:
        ach = json.loads(ach)
    else:
        ach = []
    title = request.form.get('performance_title')
    if request.form.get('scale'):
        scale = int(request.form.get('scale'))
        #print(scale)
        jsoni, agei = ez_update(cat, title, scale,comment)
        agei = child_age
        #print(plan[agei][category])
        ach = db.execute('select achievements from children where user_id=?', session["user_id"])[0]['achievements']
        if ach is None:
            ach = []
        else:
            ach = json.loads(ach)
        for p in plan[agei][category]:
            if p['title'] == title:
                p['comment'] = comment
                if p['scale'] in [0, 1] and scale == 2:
                    if p not in ach:  # p needs to be added to ach
                        conf=True
                        print('b:',p['scale'], scale)
                        p['scale'] = scale
                        p['category'] = category
                        p['time'] = datetime.now().strftime('%Y-%m-%d')
                        #p['category'] = category
                        ach.append(p)
                        print('c:', ach)
                    db.execute('update children set(achievements)=? where user_id=?', json.dumps(ach),
                               session['user_id'])
                    cat_age = db.execute('select * from children where user_id=?', session['user_id'])[0][cat + '_age']
                    #print(cat_age, '******')
                    l = []
                    for age_range, categories in plan.items():
                        for categoryy, performances in categories.items():
                            for performance in performances:
                                scalee = performance.get("scale", -1)
                                if scalee in [0, 1]:
                                    performance["category"] = categoryy
                                    #print(performance['age'], performance['age'][0], cat_age)
                                    if categoryy == category and int(performance['age'][0]) == int(cat_age):
                                        #print('found')
                                        l.append(performance)
                    dob = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]['dob']
                    #print(int(cat_age), int(calculate_age2(dob)))
                    if l == []:  # No performances for this category at this age
                        # Get the child's date of birth and calculate the actual age
                        dob = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]['dob']
                        calculated_age = int(calculate_age2(dob))  # Calculate the age based on the date of birth

                        # Iterate over all age ranges and categories to find the minimum age where no performance has scale 0 or 1
                        next_age = None  # This will store the next valid age with no scale 0 or 1 performance
                        for age_range, categories in plan.items():
                            for categoryy, performances in categories.items():
                                if categoryy == category:  # If we're in the right category
                                    for performance in performances:
                                        # Check if the performance has scale 0 or 1 and is in the current age range
                                        if int(performance['age'][0]) == calculated_age:
                                            if performance.get('scale', -1) in [0, 1]:
                                                break  # This performance has scale 0 or 1, continue to next one
                                    else:
                                        # If no break occurred, then all performances for this age are not scale 0 or 1
                                        next_age = calculated_age
                                        break  # Exit the loop early as we've found the next age with no scale 0 or 1
                            if next_age is not None:
                                break  # Exit outer loop if we found the next valid age

                        # Update the child's age to the next valid age with no scale 0 or 1 performance
                        if next_age is not None and next_age != int(cat_age):  # Only update if there's a change in age
                            db.execute('update children set (?)=? where user_id=?', cat + '_age', next_age,
                                       session['user_id'])

                    #######
                p['scale'] = scale
                #print('oo:', scale, p)
        #print(plan[agei][category])
        filtered_performances = []
        for age_range, categories in plan.items():
            for categoryy, performances in categories.items():
                for performance in performances:
                    scalee = performance.get("scale", -1)
                    if scalee in [0, 1]:
                        performance["category"] = categoryy
                        if categoryy == category:
                            filtered_performances.append(performance)

        filtred_ach = []
        #print(ach)
        if ach:
            for i in ach:
                if 'category' in i.keys():
                    if i['category'] == category:
                        filtred_ach.append(i)
        #print('q::::', filtred_ach, filtered_performances)
        #print('q//', len(filtred_ach), len(filtered_performances))
        percentage = div(len(filtred_ach), len(filtered_performances))
        result = db.execute('select * from development_history where user_id=?', session['user_id'])
        #print(result)
        #print(result[-1])
        if result[-1]['user_id'] == session['user_id'] and result[-1]['category'] == category and result[-1][
            'percentage'] == percentage:
            print('done')
        else:
            db.execute('insert into development_history (user_id,category,percentage) values(?,?,?)',
                       session['user_id'], category, percentage)

        db.execute('update children set(development_plan)=? where user_id=?', json.dumps(plan), session["user_id"])
        if conf:
            flash(f"تم إنجاز المهارة {title} بنجاح🎉 تم إضافة المهارة الى الإنجازات 🏆", 'success')
        else:
            flash(f"تم تأكيد {title} بنجاح ", 'success')
        session['conf']=conf
        return redirect("/home")
    else:
        flash(f"لم يتم تحديد تقييم للمهارة {title}, الرجاء تحديد تقييم قبل التأكيد", 'success')
        session['conf']=conf
        return redirect("/home")
    '''#print(4444444444444444444)
    category = request.form['category']
    #print(category)
    child_age = request.form['child_age']
    #print(child_age)
    if category=='الإدراك':
        cat='cognitive'
    elif category=='اللغة':
        cat='language'
    elif category=='المساعدة الذاتية':
        cat='self_help'
    elif category=='الحركة':
        cat='motion'
    else:
        cat = 'social'

    #print(category)
    plan = json.loads(
        db.execute('select development_plan from children where user_id=?', session["user_id"])[0]['development_plan'])

    title = request.form.get('performance_title')
    if request.form.get('scale'):
        scale = int(request.form.get('scale'))
        jsoni,agei = ez_update(cat, title, scale)
        agei=child_age
        print(plan[agei][category])
        for p in plan[agei][category]:
            if p['title']==title:
                if scale==2 and p['scale'] in [0,1]:
                    ach = db.execute('SELECT achievements FROM children WHERE user_id = ?',
                                     (session['user_id'],))[0]['achievements']
                    print(ach)
                    if ach is not None:
                        ach = json.loads(ach)
                    else:
                        ach = []

                    if p not in ach:#p needs to be added to ach
                        print(p['scale'] , scale)
                        p['scale'] = scale
                        p['category']=category
                        ach.append(p)
                        filtred_ach=[]
                        for i in ach:
                            #print('s:',i)
                            if i['category']==category:
                                filtred_ach.append(i)
                        filtered_performances = []
                        for age_range, categories in plan.items():
                            for categoryy, performances in categories.items():
                                for performance in performances:
                                    scalee = performance.get("scale", -1)
                                    if scalee in [0, 1]:
                                        performance["category"] = categoryy
                                        if categoryy==category:
                                            filtered_performances.append(performance)
                        print('q::::',filtred_ach,filtered_performances)
                        print('q//',len(filtred_ach),len(filtered_performances))
                        percentage=div(len(filtred_ach),len(filtered_performances))

                        db.execute('insert into development_history (user_id,category,percentage) values(?,?,?)',
                                   session['user_id'], category, percentage)
                        db.execute('update children set(achievements)=? where user_id=?',json.dumps(ach),session['user_id'])
                        cat_age = db.execute('select * from children where user_id=?', session['user_id'])[0][
                            cat + '_age']
                        print(cat_age, '******')
                        l = []
                        for age_range, categories in plan.items():
                            for categoryy, performances in categories.items():
                                for performance in performances:
                                    scalee = performance.get("scale", -1)
                                    if scalee in [0, 1]:
                                        performance["category"] = categoryy
                                        print(performance['age'], performance['age'][0], cat_age)
                                        if categoryy == category and int(performance['age'][0]) == int(cat_age):
                                            print('found')
                                            l.append(performance)
                        dob = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]['dob']
                        print(int(cat_age), int(calculate_age2(dob)))
                        if l == [] and int(cat_age) != int(calculate_age2(dob)):
                            db.execute('update children set (?)=? where user_id=?', cat + '_age', cat_age + 1,
                                       session['user_id'])
            else:
                    p['scale']=scale
                    print(p)
        db.execute('update children set(development_plan)=? where user_id=?',json.dumps(plan),session["user_id"])
        flash(f"تم تأكيد {title} بنجاح ", 'success')
        child = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]
        name = child['name']
        img = child['photo_path']
        dob = child['dob']
        age = display_age(dob)
        n = calculate_age2(dob)
        ranges = [f'{n} – {n + 1}']
        for i in range(n):
            n -= 1
            ranges.append(f'{n} – {n + 1}')
        plan = json.loads(child['development_plan'])

        # Extract and sort the relevant performances
        filtered_performances = []
        for age_range, categories in plan.items():
            for category, performances in categories.items():
                for performance in performances:
                    scale = performance.get("scale", -1)
                    if scale in [0, 1]:
                        performance["category"] = category
                        filtered_performances.append(performance)

        # Sort the performances first by scale, then by age
        filtered_performances.sort(key=lambda x: (-x["scale"], x["age"]))
        print(filtered_performances)
        ach = child['achievements']
        if ach is not None:
            ach = json.loads(ach)
        else:
            ach = []
        return render_template("home.html", name=name,img=img,age=age,ranges=ranges,data=filtered_performances,total=len(filtered_performances)+len(ach),done=len(ach))
'''


@app.route('/activity', methods=['POST', 'GET'])
def activity():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_plan():
        flash('هذا المحتوى غير مسموح للوصل له قبل الانتهاء من تقييم الطفل. الرجاء إكمال تقييم مهارات الطفل')
        return find_assess()
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    #print(request.form)
    #print(request.args)
    #print(request.form['age_range'], request.args.get('age_range'), request.form.get('age_range'))
    #print(request.args.get('age_range'))
    if request.form:
        age_range = request.form['age_range']
    elif request.args:
        print(request.args.get('age_range'))
        age_range=request.args.get('age_range')



    dob = db.execute('select * from children where user_id=?', session['user_id'])[0]['dob']
    if age_range != '0 – 1':
        p = str(int(age_range[0]) - 1) + ' – ' + str(int(age_range[4]) - 1)
    else:
        p = ''
    if age_range != '5 – 6' and int(age_range[0]) < calculate_age2(dob):
        n = str(int(age_range[0]) + 1) + ' – ' + str(int(age_range[4]) + 1)
    else:
        n = ''
    if request.method == 'POST' and age_range:


        plan = json.loads(
            db.execute('select development_plan from children where user_id=?', (session['user_id'],))[0][
                'development_plan'])

        if age_range in plan:
            return render_template('activity.html', p=p, n=n, data=plan[age_range]['اللغة'], age_range=age_range,
                                   category='اللغة')
        else:
            flash('الرجاء إعادة تسجيل الدخول للوصول لتلك الفئة العمرية')
            return redirect('/home')
    else:
        category = request.args.get('category', 'اللغة')
        plan = json.loads(
            db.execute('select development_plan from children where user_id=?', (session['user_id'],))[0][
                'development_plan'])

        if age_range in plan:
            return render_template('activity.html', p=p, n=n, data=plan[age_range][category], age_range=age_range,
                                   category=category)
        else:
            flash('الرجاء إعادة تسجيل الدخول للوصول لتلك الفئة العمرية')
            return redirect('/home')

@app.route('/assess_self_help')
def assess_self_help():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    filtered_data = json.loads(db.execute('select self_help_json from children where user_id=?',session["user_id"])[0]['self_help_json'])
    child_age= db.execute('select self_help_age from children where user_id=?',session["user_id"])[0]['self_help_age']
    return render_template('assess_self_help.html', data=filtered_data, child_age=str(child_age), current_step=3,current_substep=5)

@app.route('/update_self_help', methods=['POST'])
def update_self_help():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # Retrieve data from the form
    title = request.form.get('performance_title')
    comment = request.form.get('comment')
    if request.form.get('scale'):
        scale = int(request.form.get('scale'))
        flash(f"تم تأكيد {title} بنجاح ", 'success')
        motion_json,motion_age=ez_update('self_help',title,scale,comment)
        return render_template('assess_self_help.html', data=motion_json, child_age=str(motion_age), current_step=3,current_substep=5)
    else:
        flash(f"لم يتم تحديد تقييم للمهارة {title}, الرجاء تحديد تقييم قبل التأكيد", 'success')
        motion_json, motion_age = ez_update('self_help', title, -1)
        return render_template('assess_self_help.html', data=motion_json, child_age=str(motion_age), current_step=3,
                               current_substep=5)


@app.route('/submit_self_help', methods=['POST'])
def submit_self_help():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # print('****:',request.form)
    performances = request.form.to_dict(flat=False)
    # print('bbbbbbbbbbbb:',request.form.to_dict(flat=False))
    data = []
    p = {}
    for i in performances:
        # print(i,performances[i])
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            # print('p:',performances[i])
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
    # print(data)
    missed = []
    for i in data:
        if 'scale' in i:
            scale = int(i['scale'])
            motion_json, motion_age = ez_update('self_help', i['title'], scale, i['comment'])
        else:
            motion_json, motion_age = ez_update('self_help', i['title'], -1, '')
            missed.append(i['title'])
    if missed:
        flash(f"لم يتم تحديد تقييم للمهارة {', '.join(missed)}, الرجاء تحديد تقييم قبل التأكيد.", 'success')
    return ez_submit('self_help','assess_self_help.html','/home','المساعدة الذاتية',0)




@app.route('/assess_cognitive')
def assess_cognitive():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    filtered_data = json.loads(db.execute('select cognitive_json from children where user_id=?',session["user_id"])[0]['cognitive_json'])
    child_age= db.execute('select cognitive_age from children where user_id=?',session["user_id"])[0]['cognitive_age']
    #data2=json.loads(db.execute('select * from children where user_id=?',session["user_id"])[0]['language_json'])
    return render_template('assess_cognitive.html', data=filtered_data, child_age=str(child_age), current_step=3,current_substep=4)

@app.route('/update_cognitive', methods=['POST'])
def update_cognitive():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # Retrieve data from the form
    title = request.form.get('performance_title')
    comment = request.form.get('comment')
    if request.form.get('scale'):
        scale = int(request.form.get('scale'))
        flash(f"تم تأكيد المهارة {title} بنجاح ", 'success')
        motion_json,motion_age=ez_update('cognitive',title,scale,comment)
        return render_template('assess_cognitive.html', data=motion_json, child_age=str(motion_age), current_step=3,current_substep=4)
    else:
        flash(f"لم يتم تحديد تقييم للمهارة {title}, الرجاء تحديد تقييم قبل التأكيد", 'success')
        motion_json, motion_age = ez_update('cognitive', title, -1)
        return render_template('assess_cognitive.html', data=motion_json, child_age=str(motion_age), current_step=3,
                               current_substep=4)


@app.route('/submit_cognitive', methods=['POST'])
def submit_cognitive():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # print('****:',request.form)
    performances = request.form.to_dict(flat=False)
    # print('bbbbbbbbbbbb:',request.form.to_dict(flat=False))
    data = []
    p = {}
    for i in performances:
        # print(i,performances[i])
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            # print('p:',performances[i])
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
    # print(data)
    missed = []
    for i in data:
        if 'scale' in i:
            scale = int(i['scale'])
            motion_json, motion_age = ez_update('cognitive', i['title'], scale, i['comment'])
        else:
            motion_json, motion_age = ez_update('cognitive', i['title'], -1, '')
            missed.append(i['title'])
    if missed:
        flash(f"لم يتم تحديد تقييم للمهارة {', '.join(missed)}, الرجاء تحديد تقييم قبل التأكيد.", 'success')
    return ez_submit('cognitive','assess_cognitive.html','/assess_self_help','الإدراك',5)






@app.route('/assess_social')
def assess_social():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    filtered_data = json.loads(db.execute('select social_json from children where user_id=?',session["user_id"])[0]['social_json'])
    child_age= db.execute('select social_age from children where user_id=?',session["user_id"])[0]['social_age']
    return render_template('assess_social.html', data=filtered_data, child_age=str(child_age), current_step=3,current_substep=3)

@app.route('/update_social', methods=['POST'])
def update_social():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # Retrieve data from the form
    title = request.form.get('performance_title')
    comment = request.form.get('comment')
    if request.form.get('scale'):
        scale = int(request.form.get('scale'))
        flash(f"تم تأكيد المهارة {title} بنجاح ", 'success')
        motion_json,motion_age=ez_update('social',title,scale,comment)
        return render_template('assess_social.html', data=motion_json, child_age=str(motion_age), current_step=3,current_substep=3)
    else:
        flash(f"لم يتم تحديد تقييم للمهارة {title}, الرجاء تحديد تقييم قبل التأكيد", 'success')
        motion_json, motion_age = ez_update('social', title, -1)
        return render_template('assess_social.html', data=motion_json, child_age=str(motion_age), current_step=3,
                               current_substep=3)

@app.route('/submit_social', methods=['POST'])
def submit_social():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # print('****:',request.form)
    performances = request.form.to_dict(flat=False)
    # print('bbbbbbbbbbbb:',request.form.to_dict(flat=False))
    data = []
    p = {}
    for i in performances:
        # print(i,performances[i])
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            # print('p:',performances[i])
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
    # print(data)
    missed = []
    for i in data:
        if 'scale' in i:
            scale = int(i['scale'])
            motion_json, motion_age = ez_update('social', i['title'], scale, i['comment'])
        else:
            motion_json, motion_age = ez_update('social', i['title'], -1, '')
            missed.append(i['title'])
    if missed:
        flash(f"لم يتم تحديد تقييم للمهارة {', '.join(missed)}, الرجاء تحديد تقييم قبل التأكيد.", 'success')
    return ez_submit('social','assess_social.html','/assess_cognitive','المخالطة الاجتماعية',4)



@app.route('/assess_lang')
def assess_lang():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    filtered_data = json.loads(db.execute('select language_json from children where user_id=?',session["user_id"])[0]['language_json'])
    child_age= db.execute('select language_age from children where user_id=?',session["user_id"])[0]['language_age']
    return render_template('assess_lang.html', data=filtered_data, child_age=str(child_age), current_step=3,current_substep=2)

@app.route('/update_lang', methods=['POST'])
def update_lang():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    title = request.form.get('performance_title')
    comment = request.form.get('comment')
    if request.form.get('scale'):
        scale = int(request.form.get('scale'))
        flash(f"تم تأكيد المهارة {title} بنجاح ", 'success')
        motion_json,motion_age=ez_update('language',title,scale,comment)
        #print(motion_json, motion_age)
        return render_template('assess_lang.html', data=motion_json, child_age=str(motion_age), current_step=3,current_substep=2)
    else:
        motion_json, motion_age = ez_update('language', title, -1)
        flash(f"لم يتم تحديد تقييم للمهارة {title}, الرجاء تحديد تقييم قبل التأكيد", 'success')
        return render_template('assess_lang.html', data=motion_json, child_age=str(motion_age), current_step=3,
                               current_substep=2)
@app.route('/submit_lang', methods=['POST'])
def submit_lang():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # print('****:',request.form)
    performances = request.form.to_dict(flat=False)
    # print('bbbbbbbbbbbb:',request.form.to_dict(flat=False))
    data = []
    p = {}
    for i in performances:
        # print(i,performances[i])
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            # print('p:',performances[i])
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
    # print(data)
    missed=[]
    for i in data:
        if 'scale' in i:
            scale = int(i['scale'])
            motion_json, motion_age = ez_update('language', i['title'], scale, i['comment'])
        else:
            motion_json, motion_age = ez_update('language', i['title'], -1, '')
            missed.append(i['title'])
    if missed:
        flash(f"لم يتم تحديد تقييم للمهارة {', '.join(missed)}, الرجاء تحديد تقييم قبل التأكيد.", 'success')

    return ez_submit('language','assess_lang.html','/assess_social','اللغة',3)




@app.route('/assess_motion')
def assess_motion():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    filtered_data = json.loads(db.execute('select motion_json from children where user_id=?',session["user_id"])[0]['motion_json'])
    child_age= db.execute('select motion_age from children where user_id=?',session["user_id"])[0]['motion_age']
    #print(filtered_data[0]['motion_json'])
    #data2 = json.loads(db.execute('select * from children where user_id=?', session["user_id"])[0]['language_json'])
    return render_template('assess_motion.html', data=filtered_data, child_age=str(child_age), current_step=3,current_substep=1,done=False)

'''@app.route('/update_motion', methods=['POST'])
def update_motion():
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return render_template('login.html')
    # Retrieve data from the form
    title = request.form.get('performance_title')
    comment = request.form.get('comment')
    if request.form.get('scale'):
        scale = int(request.form.get('scale'))
        flash(f"تم تأكيد المهارة {title} بنجاح ", 'success')
        motion_json,motion_age=ez_update('motion',title,scale,comment)
        return render_template('assess_motion.html', data=motion_json, child_age=str(motion_age), current_step=3,current_substep=1)
    else:
        motion_json, motion_age = ez_update('motion', title, -1)
        flash(f"لم يتم تحديد تقييم للمهارة {title}, الرجاء تحديد تقييم قبل التأكيد", 'success')
        return render_template('assess_motion.html', data=motion_json, child_age=str(motion_age), current_step=3,
                               current_substep=1)'''


@app.route('/save_social', methods=['POST'])
def save_social():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # print('****:',request.form)
    performances = request.form.to_dict(flat=False)
    # print('bbbbbbbbbbbb:',request.form.to_dict(flat=False))
    data = []
    p = {}
    for i in performances:
        # print(i,performances[i])
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            # print('p:',performances[i])
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
    # print(data)
    missed = []
    motion_json=''
    done=True
    for i in data:
        if 'scale' in i:
            scale = int(i['scale'])
            motion_json, motion_age = ez_update('social', i['title'], scale, i['comment'])
        else:
            done=False
    if motion_json:
        flash('تم الحفظ')
        return render_template('assess_social.html', data=motion_json, child_age=str(motion_age), current_step=3,
                               current_substep=3,done=done)
    else:
        child=db.execute('select * from children where user_id=?',session['user_id'])[0]
        flash("لا يوجد بيانات للحفظ")
        return render_template('assess_social.html', data=json.loads(child['social_json']), child_age=str(child['social_age']), current_step=3,
                               current_substep=3,done=done)



@app.route('/save_self_help', methods=['POST'])
def save_self_help():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # print('****:',request.form)
    performances = request.form.to_dict(flat=False)
    # print('bbbbbbbbbbbb:',request.form.to_dict(flat=False))
    data = []
    p = {}
    for i in performances:
        # print(i,performances[i])
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            # print('p:',performances[i])
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
    # print(data)
    missed = []
    motion_json=''
    done=True
    for i in data:
        if 'scale' in i:
            scale = int(i['scale'])
            motion_json, motion_age = ez_update('self_help', i['title'], scale, i['comment'])
        else:
            done=False
    if motion_json:
        flash('تم الحفظ')
        return render_template('assess_self_help.html', data=motion_json, child_age=str(motion_age), current_step=3,
                               current_substep=5,done=done)
    else:
        child=db.execute('select * from children where user_id=?',session['user_id'])[0]
        flash("لا يوجد بيانات للحفظ")
        return render_template('assess_self_help.html', data=json.loads(child['self_help_json']), child_age=str(child['self_help_age']), current_step=3,
                               current_substep=5,done=done)




@app.route('/save_cognitive', methods=['POST'])
def save_cognitive():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # print('****:',request.form)
    performances = request.form.to_dict(flat=False)
    # print('bbbbbbbbbbbb:',request.form.to_dict(flat=False))
    data = []
    p = {}
    for i in performances:
        # print(i,performances[i])
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            # print('p:',performances[i])
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
    # print(data)
    missed = []
    motion_json=''
    done=True
    for i in data:
        if 'scale' in i:
            scale = int(i['scale'])
            motion_json, motion_age = ez_update('cognitive', i['title'], scale, i['comment'])
        else:
            done=False
    if motion_json:
        flash('تم الحفظ')
        return render_template('assess_cognitive.html', data=motion_json, child_age=str(motion_age), current_step=3,
                               current_substep=4,done=done)
    else:
        child=db.execute('select * from children where user_id=?',session['user_id'])[0]
        flash("لا يوجد بيانات للحفظ")
        return render_template('assess_cognitive.html', data=json.loads(child['cognitive_json']), child_age=str(child['cognitive_age']), current_step=3,
                               current_substep=4,done=done)





@app.route('/save_lang', methods=['POST'])
def save_lang():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # print('****:',request.form)
    performances = request.form.to_dict(flat=False)
    # print('bbbbbbbbbbbb:',request.form.to_dict(flat=False))
    data = []
    p = {}
    for i in performances:
        # print(i,performances[i])
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            # print('p:',performances[i])
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
    # print(data)
    missed = []
    motion_json=''
    done=True
    for i in data:
        if 'scale' in i:
            scale = int(i['scale'])
            motion_json, motion_age = ez_update('language', i['title'], scale, i['comment'])
        else:
            done=False
    if motion_json:
        flash('تم الحفظ')
        return render_template('assess_lang.html', data=motion_json, child_age=str(motion_age), current_step=3,
                               current_substep=2,done=done)
    else:
        child=db.execute('select * from children where user_id=?',session['user_id'])[0]
        flash("لا يوجد بيانات للحفظ")
        return render_template('assess_lang.html', data=json.loads(child['language_json']), child_age=str(child['language_age']), current_step=3,
                               current_substep=2,done=done)

@app.route('/save_motion', methods=['POST'])
def save_motion():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # print('****:',request.form)
    performances = request.form.to_dict(flat=False)
    # print('bbbbbbbbbbbb:',request.form.to_dict(flat=False))
    data = []
    p = {}
    for i in performances:
        # print(i,performances[i])
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            # print('p:',performances[i])
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
    # print(data)
    missed = []
    motion_json=''
    done=True
    for i in data:
        if 'scale' in i:
            scale = int(i['scale'])

            motion_json, motion_age = ez_update('motion', i['title'], scale, i['comment'])
        else:
            done=False
    if motion_json:
        flash('تم الحفظ')
        return render_template('assess_motion.html', data=motion_json, child_age=str(motion_age), current_step=3,
                               current_substep=1,done=done)
    else:
        child=db.execute('select * from children where user_id=?',session['user_id'])[0]
        flash("لا يوجد بيانات للحفظ")
        return render_template('assess_motion.html', data=json.loads(child['motion_json']), child_age=str(child['motion_age']), current_step=3,
                               current_substep=1,done=done)

@app.route('/submit_motion', methods=['POST'])
def submit_motion():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    #print('****:',request.form)
    performances=request.form.to_dict(flat=False)
    #print('bbbbbbbbbbbb:',request.form.to_dict(flat=False))
    data=[]
    p={}
    for i in performances:
        #print(i,performances[i])
        if 'title' in i:
            if p!={}:
                data.append(p)
            p={}
            p['title']=performances[i][0]
        elif 'age' in i:
            p['age']=performances[i][0]
        elif '[performance]' in i:
            #print('p:',performances[i])
            p['performance']=performances[i][0]
        elif 'scale' in i:
            p['scale']=performances[i][0]
        else:
            p['comment']=performances[i][0]
    if p != {}:
        data.append(p)
    #print(data)
    missed = []
    for i in data:
        if 'scale' in i:
            scale = int(i['scale'])
            motion_json, motion_age = ez_update('motion', i['title'], scale, i['comment'])
        else:
            motion_json, motion_age = ez_update('motion', i['title'], -1, '')
            missed.append(i['title'])
    if missed:
        flash(f"لم يتم تحديد تقييم للمهارة {', '.join(missed)}, الرجاء تحديد تقييم قبل التأكيد.", 'success')
    return ez_submit('motion','assess_motion.html','/assess_lang','الحركة',2)

@app.route("/home_tut", methods=["GET", "POST"])
def home_tut():
    return render_template('home_tut.html')


@app.route("/home", methods=["GET", "POST"])
def home():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_plan():
        flash('هذا المحتوى غير مسموح للوصل له قبل الانتهاء من تقييم الطفل. الرجاء إكمال تقييم مهارات الطفل')
        return find_assess()
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')


    user_id = session.get("user_id")
    if user_id is None:
        flash("الرجاء قم بتسجيل الدخول لعرض هذه الصفحة")
        return redirect("/login")
    child = db.execute("SELECT * FROM children WHERE user_id = ?", user_id)[0]
    name = child['name']
    img = child['photo_path']
    dob = child['dob']
    age = display_age(dob)
    n = calculate_age2(dob)
    disability = child['disability']
    chosen = f'{n - 2} – {n - 1}'
    if n > 5:
        n=5
    gender = child['gender']
    ranges = [f'{n} – {n + 1}']
    for i in range(n):
        n -= 1
        ranges.append(f'{n} – {n + 1}')
    plan = json.loads(child['development_plan'])
    filtered_performances = []
    selected_category = request.args.get("category")
    selected_age_range = request.args.get("age_range")
    selected_scale = request.args.get("scale")
    total=0
    for age_range, categories in plan.items():
        for category, performances in categories.items():
            for performance in performances:
                scale = performance.get("scale", -1)
                performance["category"] = category
                performance_age = performance.get("age")
                if scale in[0,1]:
                    total+=1
                if scale<0 or scale==2:
                    continue
                if (selected_category and category != selected_category):
                    continue
                if (selected_age_range and performance_age != selected_age_range):
                    continue
                if (selected_scale and str(scale) != selected_scale):
                    continue

                filtered_performances.append(performance)
    filtered_performances.sort(key=lambda x: (-x["scale"], x["age"]))
    ach = child['achievements']
    if ach is not None:
        ach = json.loads(ach)
    else:
        ach = []
    if 'conf' not in session:
        session['conf'] = False
    conf = session['conf']
    session['conf'] = False
    return render_template("home.html", conf=conf, name=name, img=img, age=age, ranges=ranges,
                           data=filtered_performances, total=total + len(ach), done=len(ach),
                           gender=gender, disability=disability, chosen=chosen,selected_scale=selected_scale,selected_category=selected_category,selected_age_range=selected_age_range)


@app.route("/")
def index():
    return render_template("index.html")





@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "POST":
        search_query = request.form.get("search_query", "")
        selected_age = request.form.get("age", "")
        selected_category = request.form.get("category", "")
        search_words = search_query.strip().lower().split()
        similarity_threshold = 90
        results = []
        for category, items in data.items():
            for item in items:
                performance_text = item["performance"].lower()
                similarity_score = 0
                if search_words:
                    for search_word in search_words:
                        similarity_score = max(similarity_score, fuzz.partial_ratio(search_word, performance_text))
                if search_query:
                    if (similarity_score >= similarity_threshold) and (not selected_age or selected_age in item.get("age", "")) and \
                            (not selected_category or selected_category == category):
                        results.append({"category": category, "title": item["title"],"age": item.get("age", "N/A"),
                            "performance": item["performance"],"suggested_activities": item["suggested_activities"],"similarity_score": similarity_score
                        })
                else:
                    if (not selected_age or selected_age in item.get("age", "")) and (not selected_category or selected_category == category):
                        results.append({"category": category,"title": item["title"],"age": item.get("age", "N/A"),
                            "performance": item["performance"],"suggested_activities": item["suggested_activities"],"similarity_score": similarity_score
                        })
        results.sort(key=lambda x: x["similarity_score"], reverse=True)
        if not results:
            results = 'لا يوجد نتائج'
        return render_template("search.html", results=results, search_query=search_query, selected_age=selected_age,selected_category=selected_category, data=data)
    else:
        return render_template("search.html", results=[], search_query="", selected_age="", selected_category="", data=data)


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "POST":
        child_gender = request.form.get("child_gender")
        child_name = request.form.get("child_name").capitalize()
        date_of_birth = request.form.get("date_of_birth")
        disability = request.form.get("disability") == 'yes'

        if not child_gender or not child_name or not date_of_birth:
            flash("الرجاء إدخال كافة المعلومات")
            return redirect('/setup')


        dob = datetime.strptime(date_of_birth, '%Y-%m-%d')
        age = (datetime.now() - dob).days

        if not 0<=(age//365) < 6 and not disability:
            flash("يجب أن يكون عمر الطفل 5 سنوات أو أقل")
            return redirect('/setup')
        elif (not 0<=(age//365) < 8) and disability:
            flash("ان كان الطفل من ذوي الاحتياجات الخاصة يجب ان يكون عمر الطفل 7 سنوات أو أقل")
            return redirect('/setup')
        if 'img' in request.files and request.files['img'].filename != '':
            file = request.files['img']
            resized_path = process_image(file, app.config['UPLOAD_FOLDER'])

            if resized_path is None:
                flash("الصورة الأولى ليست صورة صالحة.")
                return redirect("/register2")
        else:
            resized_path ='static/defult/img_1.png'

        # Ensure user registration data is in session
        if "temp_user" not in session:
            flash("معلومات التسجيل مفقودة. يرجى التسجيل مرة أخرى.")
            return redirect('/register')


        # Save the user's registration data to the database
        temp_user = session.pop("temp_user")
        user_id = db.execute("INSERT INTO users (username, hash, email,img) VALUES(?, ?, ?,?)",
                             temp_user["username"].lower(), generate_password_hash(temp_user["password"]),temp_user['email'],'static/unknown.png')
        print(user_id)
        db.execute('update users set name=? where id=?','User_'+str(user_id),user_id)
        data = load_data()
        child_age = age//356 #should be the defult age of all categories
        if disability:
            child_age-=2
        if child_age < 0:
            child_age = 0
        filtered_data = filter_by_age(data, child_age)
        print(filtered_data,'cccccc')
        with open('filtered_cards.json', 'w', encoding='utf-8') as f:
            json.dump(filtered_data, f, ensure_ascii=False, indent=4)
        with open('filtered_cards.json', 'r', encoding='utf-8') as f:
            motion_json = json.load(f)
            db.execute("INSERT INTO children (user_id, gender, name, dob, disability, photo_path,motion_json,motion_age,language_json,language_age,social_json,social_age,cognitive_json,cognitive_age,self_help_json,self_help_age) VALUES (?, ?, ?, ?, ?, ?,?,?,?,?,?,?,?,?,?,?)",
                              user_id, child_gender, child_name, dob, disability, resized_path,json.dumps(motion_json['الحركة']),child_age,json.dumps(motion_json['اللغة']),child_age,json.dumps(motion_json['المخالطة الاجتماعية']),child_age,json.dumps(motion_json['الإدراك']),child_age,json.dumps(motion_json['المساعدة الذاتية']),child_age)

        # Set the user_id in the session
        session["user_id"] = user_id
        session['user_type']='p'
        return redirect("/assess_motion")
    else:
        return render_template("setup.html",current_step=2)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            flash("اسم المستخدم أو كلمة المرور فارغة.")
            return redirect('/register')
        if not is_english_letters(username):
            flash("اسم المستخدم يجب ان يكون بالحروف الانجليزية")
            return redirect('/register')
        if db.execute("SELECT * FROM users WHERE username = ?", username):
            flash("اسم المستخدم موجود بالفعل. اختر اسم اخر.")
            return redirect('/register')
        if password != confirmation:
            flash("كلمة المرور غير مطابقة.")
            return redirect('/register')
        if len(password) < 5:
            flash("يجب أن تكون كلمة المرور أطول من 5 أحرف")
            return redirect('/register')
        emails=db.execute('select email from users')
        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_pattern,email):
            flash('الرجاء إدخال عنوان بريد إلكتروني صحيح')
            return redirect('/register')
        for e in emails:
            if e['email']==email:
                flash('هذا البريد الكتروني مستخدم مسبقا. الرجاء إختيار عنوان بريد الكتروني اخر')
                return redirect('/register')
        has_num = any(char.isdigit() for char in password)

        if not has_num:
            flash("يجب أن تحتوي كلمة المرور على رقم واحد على الأقل.")
            return redirect('/register')

        # Temporarily store user registration data in session
        session["temp_user"] = {
            "username": username,
            "password": password,
            'email':email
        }
        return redirect("/setup")
    else:
        return render_template("register.html",current_step=1)

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash("الرابط غير صالح أو منتهي الصلاحية")
        return redirect(url_for('forgot_password'))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not new_password or not confirm_password:
            flash("يجب إضافة كلمة المرور وتأكيد كلمة المرور")
            return render_template("reset_password.html", token=token)

        if new_password != confirm_password:
            flash("كلمتا المرور غير متطابقتين")
            return render_template("reset_password.html", token=token)

        hash_password = generate_password_hash(new_password)
        if session['user_type']=='p':
            db.execute("UPDATE users SET hash = ? WHERE email = ?", hash_password, email)
        else:
            db.execute("UPDATE specialist SET hash = ? WHERE email = ?", hash_password, email)
        flash("تم إعادة تعيين كلمة المرور بنجاح")
        return redirect('/login')

    return render_template("reset_password.html", token=token)




@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        if not email:
            flash("يجب إضافة البريد الإلكتروني")
            return render_template("forgot_password.html")
        if session['user_type']=='p':
            user = db.execute("SELECT * FROM users WHERE email = ?", email)
        else:
            user = db.execute("SELECT * FROM specialist WHERE email = ?", email)
        if not user:
            flash("البريد الإلكتروني غير موجود")
            return render_template("forgot_password.html")

        token = s.dumps(email, salt='password-reset-salt')
        reset_url = url_for('reset_password', token=token, _external=True)
        send_email(email, reset_url,user)
        flash("تم إرسال بريد إلكتروني يحتوي على رابط إعادة تعيين كلمة المرور")
        return redirect('/forgot_password')
    return render_template("forgot_password.html")



@app.route("/approved", methods=["GET", "POST"])
def approved():
    if not session['user_type'] == 'a':
        flash('هذه الصفحة فقط للمسوؤلين')
        return redirect(find_home())
    l = db.execute('select * from specialist where approved=1')
    now = datetime.now().year
    for i in l:
        # print(i)
        i['grad_year'] = now - i['grad_year']
        dob = i['dob']
        i['dob'] = calculate_age2(dob)
        print(i['dob'])
    return render_template('approved.html',l=l,now=now)





@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session['user_type'] == 'a':
        flash('هذه الصفحة فقط للمسوؤلين')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    l=db.execute('select * from specialist where approved=0')
    return render_template('admin.html',l=l)


@app.route("/login_s", methods=["GET", "POST"])
def login_s():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("يجب إضافة اسم المستخدم وكلمة المرور")
            return redirect('/login_s')
        x = db.execute("SELECT * FROM admins WHERE username = ?", username)
        if len(x) == 1:
            x = x[0]
            #d = generate_password_hash('admin0')
            if check_password_hash(x['hash'], password):
                session["user_id"] = x["id"]
                session['user_type']='a'
                return redirect('/admin')
        rows = db.execute("SELECT * FROM specialist WHERE username = ?", username.lower())
        if rows:
            if rows[0]['approved']==1:
                if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
                    flash("اسم المستخدم أو كلمة المرور غير صحيحة")
                    return redirect('/login_s')
                session["user_id"] = rows[0]["id"]
                session['user_type'] = 's'
                return redirect('/recent_chats')
            else:
                flash('عذرا لا يمكنك استخدام حساب اخصائي الا ان يتم الموافقة على تعينك ضمن الاخصائين, سيتم ارسال بريد الكتروني في حال قبولك')
                return redirect('/')
        else:
            flash("لم يتم العثور على مستخدم بهذا الاسم")
            return redirect('/login_s')
    else:
        return render_template("login_s.html")

@app.route("/login_p", methods=["GET", "POST"])
def login_p():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("يجب إضافة اسم المستخدم وكلمة المرور")
            return redirect('/login_p')
        x = db.execute("SELECT * FROM admins WHERE username = ?", username)
        if len(x) == 1:
            x = x[0]
            if check_password_hash(x['hash'], password):
                session["user_id"] = x["id"]
                session['user_type'] = 'a'
                return redirect('/admin')
        rows = db.execute("SELECT * FROM users WHERE username = ?", username.lower())
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("اسم المستخدم أو كلمة المرور غير صحيحة")
            return redirect('/login_p')
        session["user_id"] = rows[0]["id"]
        session['user_type']='p'
        return find_assess()
    else:
        return render_template("login_p.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user_id' in session and session['user_type']=='p':
        return find_assess()
    if request.method == "POST":
        if request.form.get('type')=='p':
            session['user_type']='p'
            return redirect('/login_p')
        else:
            session['user_type']='s'
            return redirect('/login_s')
    else:
        return render_template('login.html')

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return render_template('login.html')
if __name__ == "__main__":
    app.run(debug=True)




