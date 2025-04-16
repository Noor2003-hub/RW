import json
import datetime
from flask import session
from datetime import datetime, timedelta
from collections import defaultdict
with open('cards.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

import re

def normalize_arabic(text):
    # Remove diacritics
    text = re.sub(r'[\u064B-\u065F]', '', text)

    # Normalize letters
    substitutions = {
        'أ': 'ا', 'إ': 'ا', 'آ': 'ا',
        'ى': 'ي', 'ؤ': 'و', 'ئ': 'ي',
        'ة': 'ه', 'گ': 'ك'
    }
    for src, target in substitutions.items():
        text = text.replace(src, target)

    # Optional light stemming (remove common prefixes/suffixes)
    prefixes = ['ال', 'و', 'ف', 'ب', 'ك', 'ل', 'لل', 'ت', 'ي']
    suffixes = ['ه', 'ها', 'هم', 'كما', 'نا', 'ي', 'ك', 'ه', 'ة', 'ات', 'ان', 'ين', 'ون', 'وا']

    words = text.split()
    normalized_words = []
    for word in words:
        # Remove prefix
        for p in prefixes:
            if word.startswith(p) and len(word) > len(p) + 2:
                word = word[len(p):]
                break
        # Remove suffix
        for s in suffixes:
            if word.endswith(s) and len(word) > len(s) + 2:
                word = word[:-len(s)]
                break
        normalized_words.append(word)

    return ' '.join(normalized_words)


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
    #print(session.get("user_id"))
    if session.get("user_id") is not None:
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
        # for p in performances:
        # print(p['age'],calculate_age2(p['age']),age)
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
                        if not any(existing_item['title'] == item['title'] for existing_item in
                                   age_ranges_data[age_range][category]):
                            age_ranges_data[age_range][category].append(item)
                        break

    return age_ranges_data


def filter_category_by_age(data, age):
    filtered_data = []
    for p in data:
        if calculate_age2(p['age']) == int(age):
            filtered_data.append(p)
    return filtered_data
def find_home():#return user to home according to user type
    if not session: #if no user loged in= guest
        return '/'
    else:
        if session['user_type']=='p':
            return '/home'
        elif session['user_type']=='s':
            return '/recent_chats'
        else:
            return '/admin'
def is_english_letters(string):
    return all('a' <= char.lower() <= 'z' for char in string if char.isalpha())

def filter_data(time_range, organized_data):
    end_date = datetime.now().date()

    if time_range == 'week':
        # Get data for the last week
        start_date = end_date - timedelta(days=7)
        filtered_data = {}
        for category, records in organized_data.items():
            filtered_data[category] = [
                record for record in records
                if start_date <= datetime.strptime(record['time'], '%Y-%m-%d').date() <= end_date
            ]


    elif time_range == 'month':

        # Get data for the last month and aggregate by week

        start_date = end_date - timedelta(days=30)

        weekly_data = defaultdict(list)

        for category, records in organized_data.items():

            for record in records:

                record_date = datetime.strptime(record['time'], '%Y-%m-%d').date()

                if start_date <= record_date <= end_date:
                    # Determine the start date of the week for the record

                    week_start_date = record_date - timedelta(days=record_date.weekday())

                    weekly_data[(category, week_start_date)].append(record)

        # Convert weekly_data to a list of records aggregated by week

        filtered_data = {}

        for (category, week_start_date), records in weekly_data.items():

            if category not in filtered_data:
                filtered_data[category] = []

            # Aggregate percentage for the week (you can choose the logic for aggregation)

            aggregated_percentage = sum(record['percentage'] for record in records) / len(records)

            filtered_data[category].append({

                'time': week_start_date.strftime('%Y-%m-%d'),  # Use the start date of the week

                'percentage': aggregated_percentage

            })

    elif time_range == 'year':
        # Get data for the last year and aggregate by month
        start_date = end_date - timedelta(days=365)
        monthly_data = defaultdict(list)

        for category, records in organized_data.items():
            for record in records:
                record_date = datetime.strptime(record['time'], '%Y-%m-%d').date()
                if start_date <= record_date <= end_date:
                    # Determine the month and year for the record
                    month_year = record_date.strftime("%Y-%m")
                    monthly_data[(category, month_year)].append(record)

        # Convert monthly_data to a list of records aggregated by month
        filtered_data = {}
        for (category, month), records in monthly_data.items():
            if category not in filtered_data:
                filtered_data[category] = []
            # Aggregate percentage for the month (you can choose the logic for aggregation)
            aggregated_percentage = sum(record['percentage'] for record in records) / len(records)
            filtered_data[category].append({
                'time': month,
                'percentage': aggregated_percentage
            })

    else:
        # Default to week if the time_range is invalid
        start_date = end_date - timedelta(days=7)
        filtered_data = {}
        for category, records in organized_data.items():
            filtered_data[category] = [
                record for record in records
                if start_date <= datetime.strptime(record['time'], '%Y-%m-%d').date() <= end_date
            ]

    return filtered_data

def div(a,b):
    if a==0:
        return 0
    else:
        ans=round((a/(a+b))*100,1)
        if int(ans)==ans:
            return int(ans)
        else:
            return ans
def display_age(birth_date):
    birth_date = datetime.strptime(birth_date, '%Y-%m-%d %H:%M:%S')
    current_date = datetime.now()
    age_in_days = (current_date - birth_date).days

    if age_in_days < 1:
        return "حديث الولادة"
    elif age_in_days < 7:
        return f"{age_in_days} أيام"
    elif age_in_days < 30:
        weeks = age_in_days // 7
        return f"{weeks} أسابيع "
    elif age_in_days < 365:
        months = age_in_days // 30
        return f"{months} أشهر "
    else:
        years = age_in_days // 365
        return f"{years} سنوات "











