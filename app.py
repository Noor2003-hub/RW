import os
import random
from collections import defaultdict
from datetime import datetime, timedelta
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
from flask_session import Session
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from PIL import Image, UnidentifiedImageError
import numpy as np
import matplotlib.pyplot as plt
import json
import base64
from rapidfuzz import fuzz
from cs50 import SQL
from helpers import display_age, div, filter_data, is_english_letters,find_home,filter_category_by_age,create_age_ranges_structure,filter_by_age,calculate_age2,save_data,load_data,check_session
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
# Conffigure constantss
MAX_FILE_SIZE = 2 * 1024 * 1024  # Max upload file size (2MB)
ENCRYPTION_KEY = 'EE_TQZC1dolC7MvOufqONuIBscclbe8FuKJTQ6hcGPw='  # Encryption key
UPLOAD_FOLDER = 'static/uploads/'  # Directory for uploaded files
# color schemes for each category
colors = [['rgb(255, 99, 132)', 'rgba(255, 99, 132, 0.5)'],
          ['rgb(255, 159, 64)', 'rgba(255, 159, 64, 0.5)'],
          ['rgb(75, 192, 192)', 'rgba(75, 192, 192, 0.5)'],
          ['rgb(54, 162, 235)', 'rgba(54, 162, 235, 0.5)'],
          ['rgb(153, 102, 255)', 'rgba(153, 102, 255, 0.5)']]

# Initialize Flask app
app = Flask(__name__)

# Configure secret key for session and URL serialization
app.config['SECRET_KEY'] = "9a12b12c5d76f47a5e3d4f2877b2c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b4"
if not app.config['SECRET_KEY']:
    raise ValueError("No SECRET_KEY set for Flask application")

# Configure mail server settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'parent.guide.4u@gmail.com'
app.config['MAIL_PASSWORD'] = 'xoxy lyxt dyoc rwzq'  # Replace with a secure password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Initialize Flask-Mail
mail = Mail(app)

# Initialize URLSafeTimedSerializer with the secret key
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Load JSON data for cards
with open('cards.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure file upload settings
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # Ensure folder exists

# Configure CS50 library to use SQLite database
db = SQL("sqlite:///project.db")
db.execute("PRAGMA foreign_keys = ON;")  # Enable foreign key constraints

# Initialize encryption cipher
cipher_suite = Fernet(ENCRYPTION_KEY)

# Function to send a password reset email to a user
def send_email(to, reset_url, user):
    # Create a message object with subject, sender, and recipient
    msg = Message('إعادة تعيين كلمة المرور الخاصة بك - الإجراء مطلوب', sender=app.config['MAIL_USERNAME'], recipients=[to])
    name = user[0]['username']  # Extract the username
    # Construct the email body with the user's name and reset URL
    msg.body = f'''{name}،

لقد طلبت مؤخرًا إعادة تعيين كلمة المرور الخاصة بك لخدمتنا. انقر على الرابط أدناه لإعادة تعيين كلمة المرور الخاصة بك بشكل آمن:

{reset_url}

إذا لم تطلب إعادة تعيين كلمة المرور هذه، فيرجى تجاهل هذا البريد الإلكتروني. سيظل حسابك آمنًا.

شكرًا لك،
ParentGuide '''
    try:
        # Attempt to send the email
        mail.send(msg)
    except:
        # Handle the case where sending the email fails
        print('cant send msg')

# Function to send a birthday congratulation email with a new age category announcement
def send_email2(user):
    # Query the database for the child's information
    child = db.execute('select * from children where user_id=?', session['user_id'])[0]
    child_name = child['name']  # Extract the child's name
    child_age = display_age(child['dob'])  # Calculate the child's age
    # Create a message object with subject, sender, and recipient
    msg = Message(f'تهانينا بمناسبة عيد ميلاد {child_name} وافتتاح فئة عمرية جديدة! 🥳🎊', sender=app.config['MAIL_USERNAME'], recipients=[user['email']])
    name = user['username']  # Extract the parent's username
    # Construct the email body with details about the new age category
    msg.body = f'''مرحبًا {name}،

يسرنا أن نتقدم بأحر التهاني وأطيب التبريكات بمناسبة عيد ميلاد طفلكم العزيز وإتمامه {child_age}. نتمنى له دوام الصحة والسعادة.

تأكد من ان تتطلع على الفئة العمرية الجديدة عبر تطبيقنا، تتضمن مجموعة من المهارات والأنشطة الجديدة المصممة خصيصًا لتتناسب مع احتياجات وتطور طفلكم في هذه المرحلة.

شكرًا لثقتكم المستمرة بنا ونتطلع إلى مزيد من النجاحات معكم ومع أطفالكم الأعزاء.

مع أطيب التحيات،
ParentGuide '''
    try:
        # Attempt to send the email
        mail.send(msg)
    except:
        # Handle the case where sending the email fails
        print('cant send msg')

# Function to send an email to inform a user that their account has been approved
def send_email3(user):
    # Create a message object with subject, sender, and recipient
    msg = Message(f'تم قبول الانضمام الى موقعنا', sender=app.config['MAIL_USERNAME'], recipients=[user['email']])
    user_name = user['name']  # Extract the user's name
    login_link = url_for('login', _external=True)  # Generate the login URL
    index_link = url_for('index', _external=True)  # Generate the index URL
    # Construct the email body with login and index page links
    msg.body = f'''مرحبًا {user_name}،

تم قبولك في طاقم عمل موقعنا parentguide

يمكنك الآن تسجيل الدخول من هنا:
{login_link}

وسوف تتمكن من استخدام الموقع والرد على أسئلة المستخدمين فيما يتعلق بالأطفال.

أو يمكنك زيارة موقعنا:
{index_link}

مع تحيات فريق ParentGuide
'''
    try:
        # Attempt to send the email
        mail.send(msg)
    except:
        # Handle the case where sending the email fails
        print('cant send msg')

# Function to notify a specialist of a new message
def send_email4(specialist):
    # Query the database for the user sending the message
    user = db.execute('SELECT * FROM users WHERE id=?', session['user_id'])[0]
    # Create a message object with subject, sender, and recipient
    msg = Message(f' لديك رسالة جديدة 📩', sender=app.config['MAIL_USERNAME'], recipients=[specialist['email']])
    specialist_name = specialist['name']  # Extract the specialist's name
    linkk = url_for('chat', recipient_id=user['id'], _external=True)  # Generate the chat link
    # Construct the email body with the chat link
    msg.body = f'''مرحبًا {specialist_name}،

وصلتك رسالة جديدة من أحد مستخدمي موقعنا ParentGuide.

الرجاء الدخول للرد على الرسالة: {linkk}

مع تحيات فريق ParentGuide
'''
    try:
        # Attempt to send the email
        mail.send(msg)
    except:
        # Handle the case where sending the email fails
        print('cant send msg')

# Function to notify a user of a new message from a specialist
def send_email5(user):
    # Query the database for the specialist sending the message
    specialist = db.execute('SELECT * FROM specialist WHERE id=?', session['user_id'])[0]
    # Create a message object with subject, sender, and recipient
    msg = Message(f' لديك رسالة جديدة 📩', sender=app.config['MAIL_USERNAME'], recipients=[user['email']])
    name1 = user['username']  # Extract the recipient's username
    name2 = specialist['name']  # Extract the specialist's name
    linkk = url_for('chat', recipient_id=specialist['id'], _external=True)  # Generate the chat link
    # Construct the email body with the chat link
    msg.body = f'''مرحبًا {name1}،

وصلتك رسالة جديدة من {name2}.

الرجاء الدخول للاطلاع على الرسالة: {linkk}

مع تحيات فريق ParentGuide
'''
    try:
        # Attempt to send the email
        mail.send(msg)
    except:
        # Handle the case where sending the email fails
        print('cant send msg')



def encrypt_message(data):#convert plain text to encrypted data encoded in URL-safe base64 format.
    encrypted_data = cipher_suite.encrypt(data.encode())  # Encrypt the plaintext string
    # Convert encrypted bytes to a URL-safe base64-encoded string for storage
    return base64.urlsafe_b64encode(encrypted_data).decode()

def decrypt_message(encrypted_data):#convert encrypted string to plain text
    # Convert base64-encoded string back to encrypted bytes
    encrypted_data = base64.urlsafe_b64decode(encrypted_data.encode())
    # Decrypt the bytes and return the original plaintext string
    return cipher_suite.decrypt(encrypted_data).decode()

#Processes an uploaded image file by verifying, resizing, and saving it.
def process_image(file, folder):
    try:
        img = Image.open(file) # Open the image file
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
    if not session['user_type'] == 'p':#ensure user is parent
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    return render_template('/assess_tut.html')


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    # Restrict access to only specialists ('s') or parents ('p')
    if not (session['user_type'] == 's' or session['user_type'] == 'p'):
        flash('هذه الصفحة فقط لاولياء الامور و الاخصائين')  # Flash a message for unauthorized access
        return redirect(find_home())  # Redirect to the appropriate home page

    # Check if the session is still valid
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')  # Notify the user about session expiry
        return redirect('/login')  # Redirect to login

    # Handle settings for parents ('p')
    if session['user_type'] == 'p':
        if request.method == 'POST':
            # Retrieve updates form data
            username = request.form.get('username').lower()
            email = request.form.get('email')
            child_name = request.form.get('child_name')
            child_img = request.files.get('child_img')

            # Fetch existing usernames and emails (excluding current user)
            emails = db.execute('select email from users where not id=?', session['user_id'])
            usernames = db.execute('select username from users where not id=?', session['user_id'])

            # Fetch current user and child information
            user = db.execute('select * from users where id=?', session['user_id'])[0]
            child = db.execute('select * from children where user_id=?', session['user_id'])[0]

            # Check for email conflicts
            for e in emails:
                if e['email'] == email:
                    flash('البريد الإلكتروني موجود بالفعل, اختر عنوان بريد اخر')  # Notify about email conflict
                    return render_template('settings.html', user=user, child=child)

            # Check for username conflicts
            for u in usernames:
                if u['username'] == username:
                    flash('اسم المستخدم موجود بالفعل, اختر اسم مستخدم اخر')  # Notify about username conflict
                    return render_template('settings.html', user=user, child=child)

            # Update user information in the database
            db.execute('update users set username=?, email=? where id=?', username, email, session['user_id'])
            current_photo_path = db.execute('select * from children where user_id=?', session['user_id'])[0][
                'photo_path']

            # Handle image upload
            if child_img and child_img.filename != '':
                try:
                    img = Image.open(child_img)
                    img.verify()  # Verify if the uploaded file is a valid image
                    img = Image.open(child_img)  # Re-open for further operations
                except (IOError, SyntaxError):
                    flash("الصورة غير صالحة. يرجى تحميل صورة صالحة.")  # Notify about invalid image
                    return redirect('/settings')

                # Remove the existing photo if it's not default
                if current_photo_path and os.path.exists(current_photo_path) and 'defult' not in current_photo_path:
                    try:
                        os.remove(current_photo_path)
                    except:
                        print('cant remove pic')

                # Save the new image in JPEG format
                filename = secure_filename(os.path.splitext(child_img.filename)[0] + '.jpg')
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                img.convert("RGB").save(file_path, format='JPEG')  # Convert and save image
                resized_path = file_path
            else:
                resized_path = current_photo_path

            # Update child information in the database
            db.execute('UPDATE children SET name = ?, photo_path = ? WHERE user_id = ?', child_name, resized_path,
                       session['user_id'])
            flash('تم التحديث بنجاح')  # Notify about successful update
            return redirect(url_for('settings'))

        # Fetch and render user and child information
        user = db.execute('select * from users where id=?', session['user_id'])[0]
        child = db.execute('select * from children where user_id=?', session['user_id'])[0]
        return render_template('settings.html', user=user, child=child)

    # Handle settings for specialists ('s')
    else:
        if request.method == 'POST':
            # Retrieve updated form data
            username = request.form.get('username').lower()
            email = request.form.get('email')
            name = request.form.get('name')
            spec = request.form.get('spec')
            dob = request.form.get('dob')
            year = request.form.get('date_of_grad')
            desc = request.form.get('desc')
            img = request.files.get('img')

            # Fetch current photo path
            current_photo_path = db.execute('select * from specialist where id=?', session['user_id'])[0]['img']

            # Handle image upload
            if img and img.filename != '':
                try:
                    img = Image.open(img)
                    img.verify()  # Verify if the uploaded file is a valid image
                    img = Image.open(img)  # Re-open for further operations
                except (IOError, SyntaxError):
                    flash("الصورة غير صالحة. يرجى تحميل صورة صالحة.")  # Notify about invalid image
                    return redirect('/settings')

                # Remove the existing photo if it's not default
                if current_photo_path and os.path.exists(current_photo_path) and 'defult' not in current_photo_path:
                    try:
                        os.remove(current_photo_path)
                    except:
                        print('cant remove pic')

                # Save the new image in JPEG format
                filename = secure_filename(os.path.splitext(img.filename)[0] + '.jpg')
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                img.convert("RGB").save(file_path, format='JPEG')  # Convert and save image
                resized_path = file_path
            else:
                resized_path = current_photo_path

            # Update specialist information in the database
            db.execute(
                'UPDATE specialist SET grad_year=?, dob=?, desc=?, spec=?, email=?, username=?, name=?, img=? WHERE id=?',
                year, dob, desc, spec, email, username, name, resized_path, session['user_id'])
            flash('تم التحديث بنجاح')  # Notify about successful update
            return redirect(url_for('settings'))

        # Fetch and render specialist information
        user = db.execute('select * from specialist where id=?', session['user_id'])[0]
        now = datetime.now().year  # Get the current year
        return render_template('settings.html', user=user, now=now)


@app.route('/approve', methods=['GET', 'POST'])
def approve():
    # Ensure only admins can access this route
    if not session['user_type'] == 'a':
        flash('هذه الصفحة فقط للمسوؤلين')  # Notify unauthorized access
        return redirect(find_home())  # Redirect unauthorized users to home

    # Get the specialist's ID from the request form
    id = request.form.get('id')
    # Update the specialist's approval status to approved
    db.execute('update specialist set approved=1 where id=?', id)
    # Set the approval date to the current date
    db.execute('update specialist set approve_date=? where id=?', datetime.now().date(), id)
    # Retrieve the specialist's details from the database
    user = db.execute('select * from specialist where id=?', id)[0]
    # Send a confirmation email to the approved specialist
    send_email3(user)
    flash('تم قبول الطلب')  # Notify success
    return redirect('/admin')  # Redirect to the admin page

@app.route('/cancle', methods=['GET', 'POST'])
def cancle():
    # Ensure only admins can access this route
    if not session['user_type'] == 'a':
        flash('هذه الصفحة فقط للمسوؤلين')  # Notify unauthorized access
        return redirect(find_home())  # Redirect unauthorized users to home

    # Get the specialist's ID from the request form
    id = request.form.get('id')
    # Retrieve the approval status of the specialist
    approved = db.execute('select approved from specialist where id=?', id)[0]['approved']
    # Retrieve the specialist's profile image path
    img = db.execute('select img from specialist where id=?', id)[0]['img']
    # Retrieve the specialist's certificate file path
    cer = db.execute('select certificate from specialist where id=?', id)[0]['certificate']

    # Remove the profile image if it exists and is not the default image
    if img != 'static/defult/unknown.jpg':
        try:
            os.remove(img)
        except:
            print('cant remove pic')  # Log failure to remove the image

    # Remove the certificate file if it exists
    try:
        os.remove(cer)
    except:
        print('cant remove pic')  # Log failure to remove the certificate

    # Debugging
    #print(id, db.execute('select * from specialist '))
    #print(id, db.execute('select * from specialist where id=?', id))

    # Remove all messages associated with the specialist
    db.execute('DELETE FROM messages WHERE specialist_id = ?', (id,))
    # Remove the specialist's record from the database
    db.execute('DELETE FROM specialist WHERE id = ?', (id,))

    # Notify the admin about the outcome (rejected request or account removal)
    if approved == 0:
        flash('تم رفض الطلب')  # Notify rejection
        return redirect('/admin')  # Redirect to the admin page
    else:
        flash('تم ازالة الحساب')  # Notify account removal
        return redirect('/approved')  # Redirect to the approved specialists page
@app.route('/register2', methods=['GET', 'POST'])
def register2():
    if request.method == "POST":
        # Debugging
        # print(request.files)


        # Extract form data
        username = request.form.get("username")
        name = request.form.get("name")
        date_of_birth = request.form.get("date_of_birth")
        date_of_grad = request.form.get("date_of_grad")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        spec = request.form.get("spec")
        desc = request.form.get("desc")

        # Ensure username contains only English letters
        if not is_english_letters(username):
            flash("اسم المستخدم يجب ان يكون بالحروف الانجليزية")
            return redirect('/register2')

        # Ensure all required fields are filled
        if not username or not password or not confirmation or not name or not date_of_birth or not date_of_grad or not email:
            flash("الرجاء اكمال الفراغات")
            return redirect("/register2")

        # Ensure username is unique
        if db.execute("SELECT * FROM specialist WHERE username = ?", username):
            flash("اسم المستخدم موجود بالفعل. اختر اسم اخر.")
            return redirect("/register2")

        # Ensure passwords match
        if password != confirmation:
            flash("كلمة المرور غير مطابقة.")
            return redirect("/register2")

        # Ensure password is sufficiently strong
        if len(password) < 5:
            flash("يجب أن تكون كلمة المرور أطول من 5 أحرف")
            return redirect("/register2")
        has_num = any(char.isdigit() for char in password)
        if not has_num:
            flash("يجب أن تحتوي كلمة المرور على رقم واحد على الأقل.")
            return redirect("/register2")

        # Ensure email is valid and unique
        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_pattern, email):
            flash('الرجاء إدخال عنوان بريد إلكتروني صحيح')
            return redirect("/register2")
        emails = db.execute('select email from specialist')
        for e in emails:
            if e['email'] == email:
                flash('هذا البريد الكتروني مستخدم مسبقا. الرجاء إختيار عنوان بريد الكتروني اخر')
                return redirect("/register2")

        # Process first image (img) - mandatory
        if 'img' in request.files and request.files['img'].filename != '':
            file = request.files['img']
            resized_path = process_image(file, app.config['UPLOAD_FOLDER'])
            if resized_path is None:
                flash("الصورة الأولى ليست صورة صالحة.")
                return redirect("/register2")
        else:
            flash('الرجاء ارفاق الشهادة')
            return redirect('/register2')

        # Process second image (img2) - optional
        if 'img2' in request.files and request.files['img2'].filename != '':
            file2 = request.files['img2']
            resized_path2 = process_image(file2, app.config['UPLOAD_FOLDER'])
            if resized_path2 is None:
                flash("الصورة الثانية ليست صورة صالحة.")
                return redirect('/register2')
        else:
            resized_path2 = 'static/defult/unknown.jpg'  # Default image if none provided

        # Insert new specialist into the database
        db.execute(
            'insert into specialist (username, hash, email, name, spec, dob, grad_year, desc, certificate, img, request_date) '
            'values (?,?,?,?,?,?,?,?,?,?,?)',
            username.lower(),
            generate_password_hash(password),
            email,
            name,
            spec,
            datetime.strptime(date_of_birth, '%Y-%m-%d').date(),
            date_of_grad,
            desc,
            resized_path,
            resized_path2,
            datetime.now().date()
        )
        flash('تم إنشاء حساب بنجاح. الرجاء انتظار بريد الكتروني بالموافقة للتمكن من استخدام حساب الاخصائي')
        return redirect("/")
    else:
        # Pass the current year to the registration template
        now = datetime.now().year
        return render_template("register2.html", now=now)



@app.route("/recent_chats")
def recent_chats():
    # Check if the user is a parent or a specialist
    if not (session['user_type'] == 's' or session['user_type'] == 'p'):
        flash('هذه الصفحة فقط لاولياء الامور و الاخصائين')
        return redirect(find_home())

    # Check if the session is still valid
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')

    user_type = session['user_type']  # Store the current user type (parent or specialist)

    if user_type == "p":
        # Retrieve recent chats for parents, including the specialist's image
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

        # Fetch parent user details
        user = db.execute('SELECT * FROM users WHERE id=?', session['user_id'])

    else:
        # Retrieve recent chats for specialists, including the user's name
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

        # Fetch specialist user details
        user = db.execute('SELECT * FROM specialist WHERE id=?', session['user_id'])

        # Set default values for recipients' names and images (if no chat exists)
        for i in recent_chats:
            i['recipient_name'] = 'User_' + str(i['recipient_id'])
            i['recipient_image'] = 'static/defult/unknown.jpg'

    now = datetime.now().year  # Get the current year
    user = user[0]  # Extract user information from the result

    # Decrypt the message content before displaying it
    for c in recent_chats:
        c['content'] = decrypt_message(c['content'])

    # Return the template for recent chats with all necessary data
    return render_template("recent_chats.html", recent_chats=recent_chats, user_type=user_type, user=user, now=now)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    # Check if the user is a parent
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())

    # Check if the session is still valid
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')

    # Fetch list of approved specialists from the database
    specialists = db.execute('SELECT * FROM specialist WHERE approved=1')
    now = datetime.now().year  # Get the current year

    # Calculate the years since graduation and the age of each specialist
    for i in specialists:
        i['grad_year'] = now - i['grad_year']  # Calculate years since graduation
        dob = i['dob']
        i['dob'] = calculate_age2(dob)  # Calculate age from the date of birth

    # Return the contact page with the specialists' details
    return render_template('contact.html', l=specialists)

#create chat url according to recipient_id
@app.route("/chat/<int:recipient_id>", methods=["GET", "POST"])
def chat(recipient_id):
    # Check if the user session is active; if not, redirect to login.
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')

    # Determine the type of user (parent or specialist).
    user_type = session.get('user_type')

    # Retrieve the recipient and sender details based on the user type.
    if user_type == "p":
        recipient = db.execute("SELECT * FROM specialist WHERE id = ?", recipient_id)[0]
        sender = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])[0]
    else:
        recipient = db.execute("SELECT * FROM users WHERE id = ?", recipient_id)[0]
        sender = db.execute("SELECT * FROM specialist WHERE id = ?", session['user_id'])[0]

    # Handle the POST request to send a message.
    if request.method == "POST":
        # Get the message content from the form.
        message = request.form.get("message")
        # Generate a timestamp for the message.
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

        # Save the message in the database and send an email notification based on the sender type.
        if user_type == 'p':
            db.execute(
                "INSERT INTO messages (user_id, specialist_id, content, timestamp, sender) VALUES (?, ?, ?, ?, ?)",
                session["user_id"], recipient_id, encrypt_message(message), timestamp, 1)
            send_email4(recipient)  # Notify the specialist.
        else:
            db.execute(
                "INSERT INTO messages (user_id, specialist_id, content, timestamp, sender) VALUES (?, ?, ?, ?, ?)",
                recipient_id, session["user_id"], encrypt_message(message), timestamp, 0)
            send_email5(recipient)  # Notify the user.

        # If the request is AJAX(Asynchronous JavaScript and XML), return the new message's HTML directly.
        if request.is_xhr:
            new_message = f"""
            <div class='my-message'>
                <span class='message-content'>{message}</span>
                <span class='timestamp-left'>{timestamp}</span>
            </div>
            """
            return new_message

        # Redirect to the chat page after processing the message.
        return redirect(url_for('chat', recipient_id=recipient_id))
    #"seen" function
    # Retrieve all messages between the sender and recipient from the database.
    messages = db.execute(
        "SELECT * FROM messages WHERE (user_id = ? AND specialist_id = ?) OR (user_id = ? AND specialist_id = ?)",
        session["user_id"], recipient_id, recipient_id, session["user_id"]
    )

    # Mark the last message as seen if it was sent by the other party.
    if messages:
        last_message = messages[-1]
        if (user_type == 'p' and last_message['sender'] == 0) or (user_type == 's' and last_message['sender'] == 1):
            db.execute("UPDATE messages SET seen = 1 WHERE id = ? AND seen = 0", last_message['id'])
        sender_id = last_message['sender'] if user_type == 'p' else 1 - last_message['sender']
        db.execute("UPDATE messages SET seen = 1 WHERE user_id = ? AND specialist_id = ? AND seen = 0",
                   sender_id, recipient_id)

        # Determine if the last message was seen by the recipient.
        seen = last_message['seen'] if (messages[-1]['sender'] == 0 and session['user_type'] == 's') or \
                                       (messages[-1]['sender'] == 1 and session['user_type'] == 'p') else False
    else:
        seen = False

    # Decrypt the content of each message before sending it to the template.
    for message in messages:
        message['content'] = decrypt_message(message['content'])
    return render_template("chat.html", recipient=recipient, messages=messages, user_type=user_type, seen=seen,
                           last=messages[-1] if messages else None)


@app.route('/view_development')
def view_development():
    # Check if the user is a parent
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')  # Flash message if not a parent
        return redirect(find_home())  # Redirect to home if not a parent

    # Ensure the child evaluation is completed
    if not check_plan():
        flash(
            'هذا المحتوى غير مسموح للوصل له قبل الانتهاء من تقييم الطفل. الرجاء إكمال تقييم مهارات الطفل')  # Flash message if evaluation is incomplete
        return find_assess()  # Redirect to assessment if not complete

    # Ensure the user session is still valid
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')  # Flash message if session expired
        return redirect('/login')  # Redirect to login if session expired

    # Retrieve child details from the database
    user_id = session.get('user_id')
    child = db.execute('SELECT * FROM children WHERE user_id=?', (user_id,))[0]

    # Calculate child's age
    age = calculate_age2(child['dob'])
    disability = child['disability']

    # Define categories and their arabic names
    categories = {
        'motion': 'الحركة',
        'language': 'اللغة',
        'cognitive': 'الإدراك',
        'social': 'المخالطة الاجتماعية',
        'self_help': 'المساعدة الذاتية'
    }

    # Determine if the child has any risk factors based on age and category data
    risk = []
    for category, arabic_name in categories.items():
        category_age = db.execute(f'SELECT {category}_age FROM children WHERE user_id=?', (user_id,))[0][
            f'{category}_age']
        if age - int(category_age) >= 2:
            risk.append(arabic_name)

    # Define the order of categories
    categories_order = ['اللغة', 'الإدراك', 'الحركة', 'المساعدة الذاتية', 'المخالطة الاجتماعية']

    # Initialize data storage for each category
    data = {cat: [] for cat in categories_order}

    # Retrieve development history data and organize it by category
    history = db.execute('SELECT * FROM development_history WHERE user_id=? ORDER BY time ASC', (user_id,))
    for record in history:
        category = categories.get(record['category'], record['category'])
        record_time = datetime.strptime(record['time'], '%Y-%m-%d %H:%M:%S')
        if category in data:
            data[category].append({
                'time': record_time,
                'percentage': record['percentage']
            })
    # Retrieve the development plan for the child
    development_plan = json.loads(
        db.execute('select development_plan from children where user_id=?', session['user_id'])[0]['development_plan'])
    # Ensure both zipped_data1 and zipped_data2 follow the same category order
    categories_order = ['اللغة', 'الإدراك', 'الحركة', 'المخالطة الاجتماعية', 'المساعدة الذاتية']

    # Determine the date range for the data
    start_date = min(record['time'].date() for records in data.values() for record in records)
    end_date = datetime.now().date()
    dates = [start_date + timedelta(days=x) for x in range((end_date - start_date).days + 1)]
    # Adjust the child's age if they have a disability
    if disability:
        age -= 2
    organized_data = {} #shows piecahrt of child according to achivments
    organized_data2 = {} #shows piecahrt of child according to thier age
    labels = set()

    for category, records in data.items():
        # Process for organized_data
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

    # iterate over development_plan after processing the data loop
    for age_range, categories in development_plan.items():
        if calculate_age2(age_range) == age:
            for category, performances in categories.items():
                # Process for organized_data2
                organized_data2[category] = []
                count, total = 0, 0
                for performance in performances:
                    total += 1
                    scale = performance.get("scale", -1)
                    if scale == 2:
                        count += 1
                organized_data2[category].append({
                    'percentage': (count / total) * 100
                })
                print(category, total, count)

    # Get the time range from the request (default is 'week')
    time_range = request.args.get('time_range', 'week')

    # Apply time range filter to the data
    organized_data = filter_data(time_range, organized_data)


    # Check if the child has a disability and any risk factors
    if disability == 0 and risk:
        risk_message = '❗⚠ تم رصد تأخر في مجال: ' + ', '.join(risk)
        risk_message += ', قد يكون مؤشر غير مطمئن. يرجى مراجعة أخصائي في اسرع وقت ممكن للتأكد من حالة طفلك.'
        flash(risk_message)

    # Create zipped data for the charts
    zipped_data = [
        [category, color, organized_data[category][-1]['percentage'] if organized_data[category] else 0]
        for category, color in zip(categories_order, colors)
    ]

    # Create zipped data for the development plan
    zipped_data2 = [
        [category, color, organized_data2[category][-1]['percentage'] if organized_data2[category] else 0]
        for category, color in zip(categories_order, colors)
    ]

    # Return the view with all the data needed for rendering the development page
    return render_template('view_development.html', zipped_data2=zipped_data2, time_range=time_range,
                           zipped_data=zipped_data, dataa=organized_data, labelz=sorted(labels), colors=colors)


def find_assess():
    # Fetch motion data from the database for the current user
    motion_json = json.loads(
        db.execute('select motion_json from children where user_id=?', session["user_id"])[0]['motion_json'])

    # Check if any item in motion data has no scale= has a scale of -1, if so redirect to '/assess_motion'
    for item in motion_json:
        if item['scale'] == -1:
            return redirect('/assess_motion')

    # Fetch language data from the database for the current user
    language_json = json.loads(
        db.execute('select language_json from children where user_id=?', session["user_id"])[0]['language_json'])

    # Check if any item in language data has no scale= has a scale of -1, if so redirect to '/assess_lang'
    for item in language_json:
        if item['scale'] == -1:
            return redirect('/assess_lang')

    # Fetch social data from the database for the current user
    social_json = json.loads(
        db.execute('select social_json from children where user_id=?', session["user_id"])[0]['social_json'])

    # Check if any item in social data has no scale= has a scale of -1, if so redirect to '/assess_social'
    for item in social_json:
        if item['scale'] == -1:
            return redirect('/assess_social')

    # Fetch cognitive data from the database for the current user
    cognitive_json = json.loads(
        db.execute('select cognitive_json from children where user_id=?', session["user_id"])[0]['cognitive_json'])

    # Check if any item in cognitive data has no scale= has a scale of -1, if so redirect to '/assess_cognitive'
    for item in cognitive_json:
        if item['scale'] == -1:
            return redirect('/assess_cognitive')

    # Fetch self-help data from the database for the current user
    self_help_json = json.loads(
        db.execute('select self_help_json from children where user_id=?', session["user_id"])[0]['self_help_json'])

    # Check if any item in self-help data has no scale= has a scale of -1, if so redirect to '/assess_self_help'
    for item in self_help_json:
        if item['scale'] == -1:
            return redirect('/assess_self_help')
    # check if new age ranges should be added, if child have passed a birthday:
    # Fetch date of birth and disability
    child = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]
    dob = child['dob']
    disability = child['disability']
    child_age = calculate_age2(dob) # Calculate child's age

    # Fetch the development plan from the database
    plan = json.loads(
        db.execute('select development_plan from children where user_id=?', (session['user_id']))[0][
            'development_plan'])

    #dictionary JSON data by category
    jsons = {'الحركة': motion_json, 'اللغة': language_json, 'الإدراك': cognitive_json,
             'المساعدة الذاتية': self_help_json, 'المخالطة الاجتماعية': social_json}

    # Adjust the child's age if it's over a certain threshold
    if child_age >= 6:
        child_age = 5

    r = str(child_age) + ' – ' + str(child_age + 1) # Define the age range to check

    # List to store age ranges that need to be added to the development plan
    ranges = []
    x = 0
    # Check if the current age range is in the development plan
    while r not in plan.keys() and (int(r[0]) < 6):
        ranges.append(r)
        x += 1
        r = str(child_age - x) + ' – ' + str((child_age + 1) - x)

    # If new age ranges were found, notify the user
    if ranges:
        flash('تم إضافة فئة عمرية جديدة! عيد ميلاد سعيد 🥳🎊')
        user = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])[0]
        send_email2(user)

    # For each range that needs to be added, load and update the data
    for range in ranges:
        data = load_data()

        # For each category, filter data by age and add it to the corresponding category
        for cate in jsons:
            jsonn2 = filter_by_age(data, child_age)[cate]

            # Set the scale of the filtered data to -2
            for i in jsonn2:
                i['scale'] = -2
            jsons[cate] += jsonn2

            # Update the database with the new data for each category
            if cate == 'اللغة':
                db.execute('update children set language_json=? where user_id=?', json.dumps(jsons[cate]),
                           session["user_id"])
            elif cate == 'الحركة':
                db.execute('update children set motion_json=? where user_id=?', json.dumps(jsons[cate]),
                           session["user_id"])
            elif cate == 'المخالطة الاجتماعية':
                db.execute('update children set social_json=? where user_id=?', json.dumps(jsons[cate]),
                           session["user_id"])
            elif cate == 'المساعدة الذاتية':
                db.execute('update children set self_help_json=? where user_id=?', json.dumps(jsons[cate]),
                           session["user_id"])
            elif cate == 'الإدراك':
                db.execute('update children set cognitive_json=? where user_id=?', json.dumps(jsons[cate]),
                           session["user_id"])

        # Add the filtered data to the development plan
        jsonn2 = filter_by_age(data, child_age)
        plan[range] = jsonn2

        # Update the development plan in the database
        db.execute('update children set(development_plan)=? where user_id=?', json.dumps(list(set(plan))), session["user_id"])

    # Redirect the user to the home page after the update
    return redirect("/home")

# check if user have created plan or not yet to acess certin pages
def check_plan():
    plan=db.execute('select development_plan from children where user_id=?',session['user_id'])[0]['development_plan']
    if plan is not None:
        return True
    else:
        return False

#Update a specific performance item in the child's data for a given category.
def ez_update(category, title, scale, comment):
    # Fetch the age associated with the category for the current user
    agee = db.execute('select * from children where user_id=?', session["user_id"])[0][category + '_age']
    # Fetch the JSON data for the specified category for the current user
    jsonn = json.loads(
        db.execute('select * from children where user_id=?', session["user_id"])[0][category + '_json'])
    # Iterate through the JSON data to find the item with the matching title
    for item in jsonn:
        if item['title'] == title:
            # Update the item's scale and comment
            item['scale'] = scale
            item['comment'] = comment
             #(f"Updated {category} - {title}: {item}")  #debugging
            break  # Exit the loop once the item is found and updated
    # Update the database with the modified JSON data for the specified category
    db.execute('update children set ?=? where user_id=?', category + '_json', json.dumps(jsonn), session["user_id"])
    # Return the updated JSON data and the associated age for the category
    return jsonn, agee


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

# Submit function to handle updating the child's developmental data.
def ez_submit(category, start, end, filter, substep):
    # Fetch the current age and JSON data for the specified category
    agee = db.execute('select * from children where user_id=?', session["user_id"])[0][category + '_age']
    jsonn = json.loads(
        db.execute('select * from children where user_id=?', session["user_id"])[0][category + '_json']
    )
    # Check if there are any items with a scale of -1 (indicating incomplete data)
    any_negative = any(int(i['scale']) == -1 for i in jsonn)
    if any_negative:
        # Notify user to complete all data entries and re-render the form
        flash('يرجى إكمال جميع البيانات')
        return render_template(start, data=jsonn, child_age=str(agee), current_step=3, current_substep=substep - 1)
    #return previous age range if needed= when all skills in that age range scaled in 0
    # Check if all items have a scale of 0 and if the age is greater than 0
    all_zero = all(int(i['scale']) == 0 for i in jsonn)
    if all_zero and agee > 0:
        # Load data for the previous age group and update the database
        agee -= 1
        data = load_data()
        jsonn2 = filter_by_age(data, agee)[filter]
        jsonn += jsonn2
        db.execute('update children set ?=? where user_id=?', category + '_json', json.dumps(jsonn), session["user_id"])
        db.execute('update children set ?=? where user_id=?', category + '_age', agee, session["user_id"])
        flash(f'يشير تقييم طفلك إلى أنه قد يستفيد من تقييم الفئة العمرية السابقة. يرجى إكمال القائمة')
        return render_template(start, data=jsonn, child_age=str(agee), current_step=3, current_substep=substep - 1)
    else:
        # Process data for current and previous age groups without returning pre-age range
        data = load_data()
        filtered_data = []
        child = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]
        dob = child['dob']
        child_age = calculate_age2(dob)
        # Add items from -previous- age ranges with a default scale and comment
        for p in data[filter]:
            if calculate_age2(p['age']) < agee:
                p['scale'] = -2 #-2 means it dont have to be scaled, unlike -1 means it needs to be scaled
                p['comment'] = ''
                filtered_data.append(p)
        jsonn = filtered_data + jsonn #combain scaled skills with unscaled skills
        filtered_data = []
        # Add items for the -current- age range
        for p in data[filter]:
            if agee < calculate_age2(p['age']) <= child_age:
                p['scale'] = -2
                p['comment'] = ''
                filtered_data.append(p)
        jsonn = jsonn + filtered_data
        db.execute('update children set ?=? where user_id=?', category + '_json', json.dumps(jsonn), session["user_id"])

        # if assessment is finished, create development plan from combining jsons of each cetegory
        if end == '/home':
            # Load child data and update their development plan
            dob = db.execute('select dob from children where user_id=?', session["user_id"])[0]['dob']
            motion_json = json.loads(
                db.execute('select * from children where user_id=?', session["user_id"])[0]['motion_json'])
            language_json = json.loads(
                db.execute('select * from children where user_id=?', session["user_id"])[0]['language_json'])
            social_json = json.loads(
                db.execute('select * from children where user_id=?', session["user_id"])[0]['social_json'])
            cognitive_json = json.loads(
                db.execute('select * from children where user_id=?', session["user_id"])[0]['cognitive_json'])
            self_help_json = json.loads(
                db.execute('select * from children where user_id=?', session["user_id"])[0]['self_help_json'])

            data = {"المساعدة الذاتية": self_help_json, 'اللغة': language_json, 'المخالطة الاجتماعية': social_json,
                    'الإدراك': cognitive_json, 'الحركة': motion_json}
            n = calculate_age2(dob)
            disability = child['disability']
            if disability == 1 and n > 6:
                n = 5
            ranges = [f'{n} – {n + 1}']
            for i in range(n):
                n -= 1
                ranges.append(f'{n} – {n + 1}')
            plan = create_age_ranges_structure(data, ranges)# create development plan in structure of age ranges
            db.execute('update children set(development_plan)=? where user_id=?', json.dumps(plan), session["user_id"])
            # Track progress in the development history
            filtered_performances = []
            for age_range, categories in plan.items():
                for category, performances in categories.items():
                    c, total = 0, 0
                    for performance in performances:
                        scale = performance.get("scale", -1)
                        if scale == 2:
                            performance["category"] = category
                            filtered_performances.append(performance)
                            c += 1
                        total += 1
                    cat_age = db.execute('select ? from children where user_id=?', category + '_age',
                                         session['user_id'])
                    if total == c and not cat_age == child_age:#if all skills in the category in that age are scaled to 2
                        db.execute('insert into development_history (user_id, category, percentage) values (?, ?, ?)',
                                   session["user_id"], category, 100)

            data2 = {"المساعدة الذاتية": 'self_help_json', 'اللغة': 'language_json',
                     'المخالطة الاجتماعية': 'social_json',
                     'الإدراك': 'cognitive_json', 'الحركة': 'motion_json'}
            for cat in data:
                existing_record = db.execute(
                    'select percentage from development_history where user_id=? and category=?',
                    session["user_id"], cat)
                if not existing_record: #if not 100% complete
                    initial_percentage = get_initial_percentage(agee, data2[cat])
                    db.execute('insert into development_history (user_id, category, percentage) values (?, ?, ?)',
                               session["user_id"], cat, initial_percentage)
        return redirect(end)


@app.route('/update', methods=['POST'])
def update():  # For activity updates
    # Ensure only parents can access this page
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())

    # Extract form data
    category = request.form['category']
    comment = request.form['comment']
    child_age = request.form['child_age']
    age_range = request.form['age_range']
    title = request.form.get('performance_title')

    # Map Arabic category to internal category name
    category_map = {
        'الإدراك': 'cognitive',
        'اللغة': 'language',
        'المساعدة الذاتية': 'self_help',
        'الحركة': 'motion',
    }
    cat = category_map.get(category, 'social')

    # Calculate the previous and next age ranges
    dob = db.execute('SELECT dob FROM children WHERE user_id=?', session['user_id'])[0]['dob']
    if age_range != '0 – 1':
        p2 = f"{int(age_range[0]) - 1} – {int(age_range[4]) - 1}"
    else:
        p2 = ''
    if age_range != '5 – 6' and int(age_range[0]) < calculate_age2(dob):
        n = f"{int(age_range[0]) + 1} – {int(age_range[4]) + 1}"
    else:
        n = ''

    # Load the development plan and achievements
    plan = json.loads(
        db.execute('SELECT development_plan FROM children WHERE user_id=?', session['user_id'])[0]['development_plan'])
    ach = db.execute('SELECT achievements FROM children WHERE user_id=?', session['user_id'])[0]['achievements']
    ach = [] if ach is None else json.loads(ach)

    # Update the skill if scale is provided
    if request.form.get('scale'):
        scale = int(request.form.get('scale'))
        _, agei = ez_update(cat, title, scale, comment)
        agei = child_age

        # Update the selected performance in the achivment
        for p in plan[agei][category]:
            if p['title'] == title:
                p['comment'] = comment

                # Remove from achievements if scale changes and it's no longer completed
                if p in ach and scale != 2:
                    ach.remove(p)
                elif scale == 2 and p not in ach:
                    # Add to achievements if marked as completed
                    p.update({'scale': scale, 'category': category, 'time': datetime.now().strftime('%Y-%m-%d')})
                    ach.append(p)

                # Update the database
                db.execute('UPDATE children SET achievements=? WHERE user_id=?', json.dumps(ach), session['user_id'])

                # Check if this category has been fully completed for this age
                if scale == 2:
                    cat_age = db.execute('SELECT {}_age FROM children WHERE user_id=?'.format(cat), session['user_id'])[0][
                        f'{cat}_age']
                    performances_to_check = [
                        perf for age_range, categories in plan.items()
                        for categoryy, performances in categories.items()
                        for perf in performances if categoryy == category and int(perf['age'][0]) == int(cat_age)
                    ]
                    if not performances_to_check and int(cat_age) != int(calculate_age2(dob)):# if all complete, change age of category
                        db.execute('UPDATE children SET {}_age=? WHERE user_id=?'.format(cat), cat_age + 1,
                                   session['user_id'])
                p['scale'] = scale

        # Calculate and update development percentage
        filtered_performances = [
            perf for age_range, categories in plan.items()
            for categoryy, performances in categories.items()
            for perf in performances if perf.get('scale', -1) in [0, 1] and categoryy == category
        ]
        filtered_achievements = [i for i in ach if i.get('category') == category]
        # Calculate progress percentage
        percentage = div(len(filtered_achievements), len(filtered_performances))
        # Update development history if changes are detected
        result = db.execute('SELECT * FROM development_history WHERE user_id=?', session['user_id'])
        if not (result and result[-1]['category'] == category and result[-1]['percentage'] == percentage):
            db.execute('INSERT INTO development_history (user_id, category, percentage) VALUES (?, ?, ?)',
                       session['user_id'], category, percentage)

        # Save the updated development plan
        db.execute('UPDATE children SET development_plan=? WHERE user_id=?', json.dumps(plan), session['user_id'])
        flash(f"تم تأكيد {title} بنجاح", 'success')
        return render_template('activity.html', n=n, p=p2, data=plan[agei][category], age_range=str(agei),
                               category=category)
    else:# if no scale is selected
        flash(f"لم يتم تحديد تقييم للمهارة {title}, الرجاء تحديد تقييم قبل التأكيد")
        return render_template('activity.html', n=n, p=p2, data=plan[child_age][category], age_range=str(child_age),
                               category=category)

@app.route('/ach', methods=['POST', 'GET'])
def ach():
    # Ensure only parents can access this route
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())

    # Ensure the child’s development plan is completed before accessing this page
    if not check_plan():
        flash('هذا المحتوى غير مسموح للوصل له قبل الانتهاء من تقييم الطفل. الرجاء إكمال إنشاء الحساب')
        return find_assess()

    # Check if the session is still active, else prompt for login
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')

    # Fetch the achievements data from the database
    data = db.execute('select achievements from children where user_id=? ', session["user_id"])[0]['achievements']

    # If there are achievements, load them into the template
    if data is not None:
        return render_template('ach.html', data=json.loads(data))  # Render template with achievements data

    # If no achievements exist, render the template with an empty data set
    else:
        return render_template('ach.html', data=data)  # Render template with no achievements


@app.route('/update2', methods=['POST'])
def update2():  # for home updates
    # Ensure only parents can access this route
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())

    conf = False  # Flag to determine if a new achievement is added
    # Extract form data
    category = request.form['category']
    comment = request.form['comment']
    child_age = request.form['child_age']

    # Map Arabic category to internal category name
    category_mapping = {
        'الإدراك': 'cognitive',
        'اللغة': 'language',
        'المساعدة الذاتية': 'self_help',
        'الحركة': 'motion'
    }
    cat = category_mapping.get(category, 'social')

    # Retrieve the child's development plan and achievements
    plan = json.loads(db.execute('select development_plan from children where user_id=?', session["user_id"])[0]['development_plan'])
    child = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]
    ach = json.loads(child['achievements']) if child['achievements'] else []

    # Retrieve performance title and scale
    title = request.form.get('performance_title')
    if request.form.get('scale'):
        scale = int(request.form.get('scale'))

        # Update performance data and handle achievements
        jsoni, agei = ez_update(cat, title, scale, comment)
        agei = child_age  # Ensure the correct age group is used

        # Check and update the development plan
        for performance in plan[agei][category]:
            if performance['title'] == title:
                performance['comment'] = comment
                if performance['scale'] in [0, 1] and scale == 2:  # If performance improves to scale 2
                    if performance not in ach:
                        conf = True
                        performance['scale'] = scale
                        performance['category'] = category
                        performance['time'] = datetime.now().strftime('%Y-%m-%d')
                        ach.append(performance)

                    # Save updated achievements to the database
                    db.execute('update children set(achievements)=? where user_id=?', json.dumps(ach), session['user_id'])

                    # Check if this category has been fully completed for this age
                    cat_age = db.execute('select * from children where user_id=?', session['user_id'])[0][cat + '_age']
                    performances_with_scales = [
                        perf for age, cats in plan.items()
                        for cat_name, performances in cats.items() if cat_name == category
                        for perf in performances if perf['scale'] in [0, 1] and int(perf['age'][0]) == int(cat_age)
                    ]
                    if not performances_with_scales:
                        dob = db.execute("SELECT * FROM children WHERE user_id = ?", session['user_id'])[0]['dob']
                        calculated_age = calculate_age2(dob)
                        next_age = next(
                            (int(perf['age'][0]) for age, cats in plan.items()
                             for cat_name, performances in cats.items() if cat_name == category
                             for perf in performances if perf['scale'] not in [0, 1]),
                            None
                        )
                        if next_age and next_age != int(cat_age):
                            db.execute('update children set (?)=? where user_id=?', cat + '_age', next_age, session['user_id'])

                # Update performance scale in the development plan
                performance['scale'] = scale

        # Calculate and update development percentage
        filtered_performances = [
            performance for age, cats in plan.items()
            for cat_name, performances in cats.items()
            for performance in performances if performance['scale'] in [0, 1] and cat_name == category
        ]
        filtered_achievements = [a for a in ach if a.get('category') == category]

        # Calculate progress percentage
        percentage = div(len(filtered_achievements), len(filtered_performances))
        # Update development history if changes are detected
        last_history = db.execute('select * from development_history where user_id=?', session['user_id'])
        if not (last_history and last_history[-1]['category'] == category and last_history[-1]['percentage'] == percentage):
            db.execute('insert into development_history (user_id, category, percentage) values (?, ?, ?)',
                       session['user_id'], category, percentage)

        # Save updated development plan
        db.execute('update children set(development_plan)=? where user_id=?', json.dumps(plan), session["user_id"])
        if conf:# if child achived scale 2
            flash(f"تم إنجاز المهارة {title} بنجاح🎉 تم إضافة المهارة الى الإنجازات 🏆", 'success')
        else:
            flash(f"تم تأكيد {title} بنجاح ", 'success')
        session['conf'] = conf #confetti displayed
        return redirect("/home")
    else:# if no scale is selected
        flash(f"لم يتم تحديد تقييم للمهارة {title}, الرجاء تحديد تقييم قبل التأكيد")
        session['conf'] = conf
        return redirect("/home")


@app.route('/activity', methods=['POST', 'GET'])
def activity():
    # Check if the user is a parent
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    # Check if the child’s development plan is completed
    if not check_plan():
        flash(
            'هذا المحتوى غير مسموح للوصل له قبل الانتهاء من تقييم الطفل. الرجاء إكمال تقييم مهارات الطفل')
        return find_assess()
    # Check if the session is still valid
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    # Handle age range
    if request.form:
        age_range = request.form['age_range']  # Get age range from form submission
    elif request.args:
        age_range = request.args.get('age_range')  # Get age range from URL query params

    # Fetch the child's date of birth from the database
    dob = db.execute('select * from children where user_id=?', session['user_id'])[0]['dob']

    # Determine previous and next age ranges based on current age range
    if age_range != '0 – 1':
        p = str(int(age_range[0]) - 1) + ' – ' + str(int(age_range[4]) - 1)  # Calculate previous age range
    else:
        p = ''  # No previous age range for '0 – 1'

    # Determine next age range if applicable
    if age_range != '5 – 6' and int(age_range[0]) < calculate_age2(dob):
        n = str(int(age_range[0]) + 1) + ' – ' + str(int(age_range[4]) + 1)  # Calculate next age range
    else:
        n = ''  # No next age range for '5 – 6' or if age exceeds current range
    # Fetch the child’s development
    plan = json.loads(
        db.execute('select development_plan from children where user_id=?', (session['user_id'],))[0][
            'development_plan'])
    # Handle POST request with age range
    if request.method == 'POST' and age_range:
        # If the age range is found in the development plan, render the activities
        if age_range in plan:
            return render_template('activity.html', p=p, n=n, data=plan[age_range]['اللغة'], age_range=age_range,
                                   category='اللغة')
        else:
            # when child pass a birthday it may add new age range, re-login will enable it
            flash('الرجاء إعادة تسجيل الدخول للوصول لتلك الفئة العمرية')
            return redirect('/home')

    # Handle GET request for the activity page
    else:
        category = request.args.get('category', 'اللغة')  # Get category from query parameters, default to 'اللغة'
        # If the age range is found in the plan, render the corresponding activity
        if age_range in plan:
            return render_template('activity.html', p=p, n=n, data=plan[age_range][category], age_range=age_range,
                                   category=category)
        else:
            flash('الرجاء إعادة تسجيل الدخول للوصول لتلك الفئة العمرية')  # Flash message if age range not found
            return redirect('/home')  # Redirect to home page if the range is not found

@app.route('/assess_self_help')
def assess_self_help():
    # Check if the user is a parent
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    # Check if the session is still valid
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')

    # Fetch the child's self-help data and age from the database
    filtered_data = json.loads(db.execute('select self_help_json from children where user_id=?', session["user_id"])[0]['self_help_json'])
    child_age = db.execute('select self_help_age from children where user_id=?', session["user_id"])[0]['self_help_age']
    return render_template('assess_self_help.html', data=filtered_data, child_age=str(child_age), current_step=3, current_substep=5)
# Same assessment for other categories:-
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
    return render_template('assess_cognitive.html', data=filtered_data, child_age=str(child_age), current_step=3,current_substep=4)
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
    return render_template('assess_motion.html', data=filtered_data, child_age=str(child_age), current_step=3,current_substep=1,done=False)

# finished all assessments

# Save scales choosen in assesment
@app.route('/save_self_help', methods=['POST'])
def save_self_help():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    performances = request.form.to_dict(flat=False)
    data = []
    p = {}
    for i in performances:
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
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
# Same save for the other categories:-
@app.route('/save_social', methods=['POST'])
def save_social():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    performances = request.form.to_dict(flat=False)
    data = []
    p = {}
    for i in performances:
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
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

@app.route('/save_cognitive', methods=['POST'])
def save_cognitive():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    performances = request.form.to_dict(flat=False)
    data = []
    p = {}
    for i in performances:
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
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
    performances = request.form.to_dict(flat=False)
    data = []
    p = {}
    for i in performances:
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
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
    performances = request.form.to_dict(flat=False)
    data = []
    p = {}
    for i in performances:
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
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


# Move from self help assessment
@app.route('/submit_self_help', methods=['POST'])
def submit_self_help():
    # Check if the user is a parent
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())

    # Check if the session is still valid
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')

    # Collect the form data into a dictionary
    performances = request.form.to_dict(flat=False)  # Get all form data as a dictionary
    p = {}  # Initialize an empty dictionary to store each individual performance data
    data = []  # Initialize an empty list to store processed data, will include multiple p's


    # Iterate through the form data and structure it
    for i in performances:
        if 'title' in i:
            if p != {}:  # If there is data already in p, add it to the 'data' list
                data.append(p)
            p = {}  # Reset the 'p' dictionary
            p['title'] = performances[i][0]  # Add the performance title to 'p'
        elif 'age' in i:
            p['age'] = performances[i][0]  # Add the child's age to 'p'
        elif '[performance]' in i:
            p['performance'] = performances[i][0]  # Add the performance data to 'p'
        elif 'scale' in i:
            p['scale'] = performances[i][0]  # Add the scale data to 'p'
        else:
            p['comment'] = performances[i][0]  # Add the comment data to 'p'

    # Add the last collected data if 'p' is not empty
    if p != {}:
        data.append(p)

    # Process each performance and update accordingly
    missed = []  # List to track missed evaluations
    for i in data:
        if 'scale' in i:  # If a scale is provided
            scale = int(i['scale'])  # Convert scale to integer
            motion_json, motion_age = ez_update('self_help', i['title'], scale, i['comment'])  # Update the performance data
        else:
            motion_json, motion_age = ez_update('self_help', i['title'], -1, '')  # If no scale is provided, mark it as missed
            missed.append(i['title'])  # Add the missed performance to the 'missed' list

    # Flash message for any missed evaluations
    if missed:
        flash(f"لم يتم تحديد تقييم للمهارة {', '.join(missed)}, الرجاء تحديد تقييم قبل التأكيد.", 'success')

    # Submit the data and redirect to the appropriate page
    return ez_submit('self_help', 'assess_self_help.html', '/home', 'المساعدة الذاتية', 0)

# Same submit (move from assessment) for other catgories:-
@app.route('/submit_cognitive', methods=['POST'])
def submit_cognitive():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    performances = request.form.to_dict(flat=False)
    data = []
    p = {}
    for i in performances:
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
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

@app.route('/submit_social', methods=['POST'])
def submit_social():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    performances = request.form.to_dict(flat=False)
    data = []
    p = {}
    for i in performances:
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
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



@app.route('/submit_lang', methods=['POST'])
def submit_lang():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    performances = request.form.to_dict(flat=False)
    data = []
    p = {}
    for i in performances:
        if 'title' in i:
            if p != {}:
                data.append(p)
            p = {}
            p['title'] = performances[i][0]
        elif 'age' in i:
            p['age'] = performances[i][0]
        elif '[performance]' in i:
            p['performance'] = performances[i][0]
        elif 'scale' in i:
            p['scale'] = performances[i][0]
        else:
            p['comment'] = performances[i][0]
    if p != {}:
        data.append(p)
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



@app.route('/submit_motion', methods=['POST'])
def submit_motion():
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')
    performances=request.form.to_dict(flat=False)
    data=[]
    p={}
    for i in performances:
        if 'title' in i:
            if p!={}:
                data.append(p)
            p={}
            p['title']=performances[i][0]
        elif 'age' in i:
            p['age']=performances[i][0]
        elif '[performance]' in i:
            p['performance']=performances[i][0]
        elif 'scale' in i:
            p['scale']=performances[i][0]
        else:
            p['comment']=performances[i][0]
    if p != {}:
        data.append(p)
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
    # Check if the user is a parent ('p')
    if not session['user_type'] == 'p':
        flash('هذه الصفحة فقط لأولياء الامور')
        return redirect(find_home())

    # Check if the user has completed the child's assessment
    if not check_plan():
        flash(
            'هذا المحتوى غير مسموح للوصل له قبل الانتهاء من تقييم الطفل. الرجاء إكمال تقييم مهارات الطفل')
        return find_assess()

    # Check if the user session has expired
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')

    # Get the current user's id from session and fetch child details from the database
    user_id = session.get("user_id")
    if user_id is None:
        flash("الرجاء قم بتسجيل الدخول لعرض هذه الصفحة")
        return redirect("/login")

    # Fetch child's details from the database
    child = db.execute("SELECT * FROM children WHERE user_id = ?", user_id)[0]
    name = child['name']
    img = child['photo_path']
    dob = child['dob']
    age = display_age(dob)  # Calculate excact age range

    n = calculate_age2(dob)  # Calculate age
    disability = child['disability']
    if n>=2:
        chosen = f'{n - 2} – {n - 1}'  # Determine the child's age range needed for disabled
    elif n<=1:
        chosen = f'0 – 1'
    if n > 5:
        n = 5  # Set maximum age group to 5
    gender = child['gender']

    # Create a list of age ranges
    ranges = [f'{n} – {n + 1}']
    for i in range(n):
        n -= 1
        ranges.append(f'{n} – {n + 1}')

    plan = json.loads(child['development_plan'])
    filtered_performances = []
    selected_category = request.args.get("category")
    selected_age_range = request.args.get("age_range")
    selected_scale = request.args.get("scale")
    total = 0

    # Filter the performances based on selected category, age range, and scale
    for age_range, categories in plan.items():
        for category, performances in categories.items():
            for performance in performances:
                scale = performance.get("scale", -1)
                performance["category"] = category
                performance_age = performance.get("age")
                if scale in [0, 1]:
                    total += 1
                if scale < 0 or scale == 2:
                    continue
                if (selected_category and category != selected_category):
                    continue
                if (selected_age_range and performance_age != selected_age_range):
                    continue
                if (selected_scale and str(scale) != selected_scale):
                    continue

                filtered_performances.append(performance)

    # Sort the performances by scale and age
    filtered_performances.sort(key=lambda x: (-x["scale"], x["age"]))

    # Fetch child's achievements from the database
    ach = child['achievements']
    if ach is not None:
        ach = json.loads(ach)
    else:
        ach = []

    # Check if the user has added new achivment
    if 'conf' not in session:
        session['conf'] = False
    conf = session['conf']
    session['conf'] = False  # no confitie displayed
    return render_template("home.html", conf=conf, name=name, img=img, age=age, ranges=ranges,
                           data=filtered_performances, total=total + len(ach), done=len(ach),
                           gender=gender, disability=disability, chosen=chosen, selected_scale=selected_scale,
                           selected_category=selected_category, selected_age_range=selected_age_range)


@app.route("/")
def index():
    return render_template("index.html")

from fuzzywuzzy import fuzz  # or use rapidfuzz
from flask import render_template, request

from fuzzywuzzy import fuzz  # or use rapidfuzz
from flask import render_template, request

from fuzzywuzzy import fuzz
from itertools import permutations

@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "POST":
        search_query = request.form.get("search_query", "").strip()
        selected_age = request.form.get("age", "")
        selected_category = request.form.get("category", "")

        similarity_threshold = 70  # Define the minimum similarity score
        results = []

        # Split the query into words
        search_words = search_query.lower().split()

        for category, items in data.items():
            for item in items:
                performance_text = item["performance"].strip().lower()
                max_similarity = 0

                # Check all permutations of the query words to ensure all orders are checked for similarity
                for perm in permutations(search_words):
                    perm_text = " ".join(perm)
                    similarity_score = fuzz.partial_ratio(perm_text, performance_text)
                    max_similarity = max(max_similarity, similarity_score)# find maximum possible order of words

                # Check conditions for filtering results
                if (max_similarity >= similarity_threshold) and \
                   (not selected_age or selected_age in item.get("age", "")) and \
                   (not selected_category or selected_category == category):
                    results.append({
                        "category": category,
                        "title": item["title"],
                        "age": item.get("age", "N/A"),
                        "performance": item["performance"],
                        "suggested_activities": item["suggested_activities"],
                        "similarity_score": max_similarity
                    })

        # Sort results by similarity score in descending order
        results.sort(key=lambda x: x["similarity_score"], reverse=True)

        # Handle case when no results are found
        if not results:
            results = 'لا يوجد نتائج'

        return render_template("search.html", results=results, search_query=search_query,
                               selected_age=selected_age, selected_category=selected_category, data=data)

    else:
        # Render initial search page with no results
        return render_template("search.html", results=[], search_query="", selected_age="", selected_category="",
                               data=data)
@app.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "POST":
        # Retrieve form data
        child_gender = request.form.get("child_gender")  # Child's gender
        child_name = request.form.get("child_name").capitalize()  # Child's name (capitalize first letter)
        date_of_birth = request.form.get("date_of_birth")  # Child's date of birth
        disability = request.form.get("disability") == 'yes'  # Whether the child has a disability

        # ensure all feilds are filed
        if not child_gender or not child_name or not date_of_birth:
            flash("الرجاء إدخال كافة المعلومات")
            return redirect('/setup')

        # Calculate child's age in days
        dob = datetime.strptime(date_of_birth, '%Y-%m-%d')  # Convert date string to datetime
        age = (datetime.now() - dob).days  # Calculate age in days

        # ensure age constraints for children without disabilities
        if not 0 <= (age // 365) < 6 and not disability:
            flash("يجب أن يكون عمر الطفل 5 سنوات أو أقل")
            return redirect('/setup')

        # ensure age constraints for children with disabilities
        elif not 0 <= (age // 365) < 8 and disability:
            flash("ان كان الطفل من ذوي الاحتياجات الخاصة يجب ان يكون عمر الطفل 7 سنوات أو أقل")
            return redirect('/setup')

        # Process uploaded image, if provided
        if 'img' in request.files and request.files['img'].filename != '':
            file = request.files['img']
            resized_path = process_image(file, app.config['UPLOAD_FOLDER'])  # Resize and save the image
            if resized_path is None:
                flash("الصورة الأولى ليست صورة صالحة.")
                return redirect("/register2")
        else:
            resized_path = 'static/defult/img_1.png'  # Use a default image if no image is provided

        # Ensure temporary user data is stored in the session
        if "temp_user" not in session:
            flash("معلومات التسجيل مفقودة. يرجى التسجيل مرة أخرى.")
            return redirect('/register')

        # Save user registration data to the database
        temp_user = session.pop("temp_user")  # Retrieve and remove temp_user from session
        user_id = db.execute("INSERT INTO users (username, hash, email, img) VALUES(?, ?, ?, ?)",
                             temp_user["username"].lower(),
                             generate_password_hash(temp_user["password"]),
                             temp_user['email'],
                             'static/defult/unknown.jpg')  # Insert user into the database

        # add the user's default name in the database
        db.execute('UPDATE users SET name = ? WHERE id = ?', 'User_' + str(user_id), user_id)

        # Loading and filtering developmental data by age
        data = load_data()
        child_age = age // 365  # Calculate the child's age in years
        if disability:
            child_age -= 2  # Adjust age for children with disabilities
        if child_age < 0:
            child_age = 0  # Ensure age does not go below 0
        # Filter data based on child's age
        filtered_data = filter_by_age(data, child_age)
        with open('filtered_cards.json', 'w', encoding='utf-8') as f:
            json.dump(filtered_data, f, ensure_ascii=False, indent=4)  # Save filtered data to JSON file

        # Load filtered data and save it into the database by category
        with open('filtered_cards.json', 'r', encoding='utf-8') as f:
            jsons = json.load(f)
            db.execute("""
                INSERT INTO children 
                (user_id, gender, name, dob, disability, photo_path,
                motion_json, motion_age, language_json, language_age, 
                social_json, social_age, cognitive_json, cognitive_age, 
                self_help_json, self_help_age)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, user_id, child_gender, child_name, dob, disability, resized_path,
                 json.dumps(jsons['الحركة']), child_age,
                 json.dumps(jsons['اللغة']), child_age,
                 json.dumps(jsons['المخالطة الاجتماعية']), child_age,
                 json.dumps(jsons['الإدراك']), child_age,
                 json.dumps(jsons['المساعدة الذاتية']), child_age)

        # Save user ID and user type in session
        session["user_id"] = user_id
        session['user_type'] = 'p'
        return redirect("/assess_motion")#start assessment
    else:
        return render_template("setup.html", current_step=2)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Retrieve form data
        username = request.form.get("username")  # Get the username input
        email = request.form.get("email")  # Get the email input
        password = request.form.get("password")  # Get the password input
        confirmation = request.form.get("confirmation")  # Get the password confirmation input

        # Check if any of the required fields are empty
        if not username or not password or not confirmation:
            flash("اسم المستخدم أو كلمة المرور فارغة.")
            return redirect('/register')

        # Ensure the username contains only English letters
        if not is_english_letters(username):
            flash("اسم المستخدم يجب ان يكون بالحروف الانجليزية")
            return redirect('/register')

        # Check if the username already exists in the database
        if db.execute("SELECT * FROM users WHERE username = ?", username):
            flash("اسم المستخدم موجود بالفعل. اختر اسم اخر.")
            return redirect('/register')

        # Check if the passwords match
        if password != confirmation:
            flash("كلمة المرور غير مطابقة.")
            return redirect('/register')

        # Ensure the password length is greater than 5 characters
        if len(password) < 5:
            flash("يجب أن تكون كلمة المرور أطول من 5 أحرف")
            return redirect('/register')

        # Check if the email format is valid
        email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_pattern, email):
            flash("الرجاء إدخال عنوان بريد إلكتروني صحيح")
            return redirect('/register')

        # Ensure the email is not already in use
        emails = db.execute('SELECT email FROM users')
        for e in emails:
            if e['email'] == email:
                flash("هذا البريد الكتروني مستخدم مسبقا. الرجاء إختيار عنوان بريد الكتروني اخر")
                return redirect('/register')

        # Ensure the password contains at least one number
        has_num = any(char.isdigit() for char in password)
        if not has_num:
            flash("يجب أن تحتوي كلمة المرور على رقم واحد على الأقل.")
            return redirect('/register')

        # Temporarily store the registration data in the session
        session["temp_user"] = {
            "username": username,  # Save the username
            "password": password,  # Save the password
            "email": email  # Save the email
        }

        # Redirect to the setup page for additional information
        return redirect("/setup")
    else:
        return render_template("register.html", current_step=1)


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # Try to decode the token and get the email, with a 1-hour expiry time.
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        # If decoding fails or the token is expired, show an error message and redirect.
        flash("الرابط غير صالح أو منتهي الصلاحية")  # Invalid or expired link
        return redirect(url_for('forgot_password'))  # Redirect to forgot password page

    if request.method == "POST":
        # Retrieve the new password and confirmation password from the form.
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Ensure both new password and confirmation password are provided.
        if not new_password or not confirm_password:
            flash("يجب إضافة كلمة المرور وتأكيد كلمة المرور")  # Prompt user to fill both fields
            return render_template("reset_password.html", token=token)  # Render the reset form again

        # Check if the new password and confirmation password match.
        if new_password != confirm_password:
            flash("كلمتا المرور غير متطابقتين")
            return render_template("reset_password.html", token=token)  # Render the form again

        # Hash the new password for security.
        hash_password = generate_password_hash(new_password)

        # Update the password in the database depending on the user type ('p' for parent, 's' for specialist).
        if session['user_type'] == 'p':
            db.execute("UPDATE users SET hash = ? WHERE email = ?", hash_password, email)
        else:
            db.execute("UPDATE specialist SET hash = ? WHERE email = ?", hash_password, email)

        # Notify the user that the password has been successfully reset.
        flash("تم إعادة تعيين كلمة المرور بنجاح")  # Password reset success
        return redirect('/login')  # Redirect to login page

    # Render the password reset page with the token passed as a parameter.
    return render_template("reset_password.html", token=token)


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        # Retrieve the email entered in the form.
        email = request.form.get("email")

        # Ensure the email field is not empty.
        if not email:
            flash("يجب إضافة البريد الإلكتروني")
            return render_template("forgot_password.html")

        # Check if the email exists in the database, based on user type ('p' for parent, 's' for specialist).
        if session['user_type'] == 'p':
            user = db.execute("SELECT * FROM users WHERE email = ?", email)
        else:
            user = db.execute("SELECT * FROM specialist WHERE email = ?", email)

        # If the email is not found, display an error message.
        if not user:
            flash("البريد الإلكتروني غير موجود")
            return render_template("forgot_password.html")
        # If the email is valid, generate a authenticaton token to reset the password.
        token = s.dumps(email, salt='password-reset-salt')
        # Create a reset URL with the token that will be used to reset the password.
        reset_url = url_for('reset_password', token=token, _external=True)
        # Send the password reset email with the reset link.
        send_email(email, reset_url, user)
        # Notify the user that the reset email has been sent.
        flash("تم إرسال بريد إلكتروني يحتوي على رابط إعادة تعيين كلمة المرور")  # Email sent message
        return redirect('/forgot_password')
    # Render the forgot password form if it's a GET request.
    return render_template("forgot_password.html")



@app.route("/approved", methods=["GET", "POST"])
def approved():
    # Check if the user is an admin, otherwise redirect to the appropriate home page
    if not session['user_type'] == 'a':
        flash('هذه الصفحة فقط للمسوؤلين')
        return redirect(find_home())

    # Fetch specialists whose approval status is 1 (approved)
    l = db.execute('select * from specialist where approved=1')
    now = datetime.now().year  # Get the current year

    # Loop through the list of approved specialists and calculate their age and graduation year
    for i in l:
        i['grad_year'] = now - i['grad_year']  # Calculate years since graduation
        dob = i['dob']  # Date of birth
        i['dob'] = calculate_age2(dob)  # Calculate age using a separate function
        #print(i['dob'])  #debugging
    return render_template('approved.html', l=l, now=now)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    # Check if the user is an admin, otherwise redirect to the appropriate home page
    if not session['user_type'] == 'a':
        flash('هذه الصفحة فقط للمسوؤلين')
        return redirect(find_home())

    # Check if the session has expired; if yes, prompt the user to log in again
    if not check_session():
        flash('انتهت جلستك. الرجاء إعادة تسجيل الدخول لرؤية هذا المحتوى')
        return redirect('/login')

    # Fetch specialists who are not approved yet (approved = 0)
    l = db.execute('select * from specialist where approved=0')
    return render_template('admin.html', l=l)


@app.route("/login_s", methods=["GET", "POST"])
def login_s():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate that the username and password are not empty
        if not username or not password:
            flash("يجب إضافة اسم المستخدم وكلمة المرور")
            return redirect('/login_s')

        # Check if the username exists in the admins table
        x = db.execute("SELECT * FROM admins WHERE username = ?", username)
        if len(x) == 1:
            x = x[0]
            # Check if the entered password matches the stored hashed password for admin
            if check_password_hash(x['hash'], password):
                session["user_id"] = x["id"]  # Store the admin's user ID in session
                session['user_type'] = 'a'  # Set user type to admin
                return redirect('/admin')
        # Check if the username exists in the specialists table
        rows = db.execute("SELECT * FROM specialist WHERE username = ?", username.lower())
        if rows:
            # Check if the specialist is approved
            if rows[0]['approved'] == 1:
                if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
                    flash("اسم المستخدم أو كلمة المرور غير صحيحة")
                    return redirect('/login_s')
                session["user_id"] = rows[0]["id"]  # Store the specialist's user ID in session
                session['user_type'] = 's'  # Set user type to specialist
                return redirect('/recent_chats')
            else: #specialist is on request queue and needs to be accepted
                flash('عذرا لا يمكنك استخدام حساب اخصائي الا ان يتم الموافقة على تعينك ضمن الاخصائين, سيتم ارسال بريد الكتروني في حال قبولك')  # Flash message if specialist is not approved
                return redirect('/')
        else:
            flash("لم يتم العثور على مستخدم بهذا الاسم")
            return redirect('/login_s')
    else:# GET
        return render_template("login_s.html")

@app.route("/login_p", methods=["GET", "POST"])
def login_p():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # ensure if both username and password are provided
        if not username or not password:
            flash("يجب إضافة اسم المستخدم وكلمة المرور")
            return redirect('/login_p')

        # Check if the username exists in the admins table
        x = db.execute("SELECT * FROM admins WHERE username = ?", username)
        if len(x) == 1:
            x = x[0]
            # If found, check if the password matches the stored hashed password for admin
            if check_password_hash(x['hash'], password):
                session["user_id"] = x["id"]  # Store the admin's user ID in session
                session['user_type'] = 'a'  # Set user type to admin
                return redirect('/admin')

        # Check if the username exists in the users (parents) table and password matches
        rows = db.execute("SELECT * FROM users WHERE username = ?", username.lower())
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("اسم المستخدم أو كلمة المرور غير صحيحة")
            return redirect('/login_p')

        # If valid, store the user's ID and set user type as parent ('p')
        session["user_id"] = rows[0]["id"]
        session['user_type'] = 'p'

        # if it is parent, check if they finished assessment
        return find_assess()

    else:
        return render_template("login_p.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Check if a parent user is logged in; if so, check if they finished assessment
    if 'user_id' in session and session['user_type'] == 'p':
        return find_assess()

    if request.method == "POST":
        # If the form is submitted, determine user type and redirect to the appropriate login page
        if request.form.get('type') == 'p':
            session['user_type'] = 'p'  # Set user type as parent
            return redirect('/login_p')
        else:
            session['user_type'] = 's'  # Set user type as specialist
            return redirect('/login_s')

    else:
        return render_template('login.html')


# Route for logging out
@app.route("/logout", methods=["GET", "POST"])
def logout():
    # Clear the session to log the user out
    session.clear()
    return render_template('login.html')
# Run the application in debug mode
if __name__ == "__main__":
    app.run(debug=True)
