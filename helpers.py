print(55)
import csv
from functools import wraps
import datetime
from flask import redirect, render_template, session
import requests
from spotifysearch.client import Client
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
import csv

import sqlite3
import json
from functools import wraps
import datetime
from flask import redirect, render_template, session
import requests
from spotifysearch.client import Client
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
from difflib import SequenceMatcher
from datetime import datetime
cid = "6accb5d452554ee9af43586b7b95ab10"
secret = "64fe5f741b444062afdf0aa4d3db7b4c"
client_credentials_manager = SpotifyClientCredentials(client_id=cid, client_secret=secret)
sp=spotipy.Spotify(client_credentials_manager=client_credentials_manager)
from datetime import datetime, timedelta
from collections import defaultdict
with open('cards.json', 'r', encoding='utf-8') as f:
    data = json.load(f)


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
        return "Newborn"
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

from datetime import datetime


def calculate_age(dob):
    """
    Calculate the age in months from the date of birth.
    """
    birth_date = datetime.strptime(dob, "%Y-%m-%d %H:%M:%S")
    today = datetime.today()
    age_in_months = (today.year - birth_date.year) * 12 + today.month - birth_date.month
    return age_in_months

def get_song_date(song,artist): #get song date of release using song name and artist of it
    check=sp.search(song+'-'+artist,type='track')
    return check['tracks']['items'][0]['album']['release_date']


def get_song_pic(song,artist): #get the album pic using song name and artist of it
    check=sp.search(song+'-'+artist,type='track')
    return check['tracks']['items'][0]['album']['images'][0]['url']


def song_name(song, artist): #takes song name and artist, and figure out if this song is for this artist, then return the song name on spotify
    check=sp.search(song+'-'+artist,type='track')
    track_name= check['tracks']['items'][0]['name']
    i=0
    if '-' in track_name or '(' in track_name or '[' in track_name:
        for letter in track_name:
            if letter in ['-','(','[']:
                return (track_name[0:i])
                break
            i+=1
    return track_name

def song_artist(song): #get most match artist name using his song title
    check=sp.search(song,type='track')
    return check['tracks']['items'][0]['album']['artists'][0]['name']



def similar(a, b): #compare 2 strings if they are similar not equal
    return SequenceMatcher(None, a, b).ratio()



def get_pic(name): #get profile picture using artist name
    if name is None:
        return name
    check =sp.search(str(name), type='artist')
    image= check['artists']['items'][0]['images']
    return str(image[0]['url'])

#t="jxKlJKxMGltwDonuGzPigBjGpHcEvStESFPviiJy"
#d = discogs_client.Client('ExampleApplication/0.1', user_token=t)

def valid_name(name): #check if name exists in spotify artists
    if name is None:
        return True
    check=sp.search(str(name), type='artist')
    if not check:
        return False
    return True

def get_name(name): #return most match name of artist on spotify
    if name is None:
        return True
    check=sp.search(str(name), type='artist')
    artist_name= check['artists']['items'][0]['name']
    return artist_name




#token="BvOyeN9cef-yzRDZC7qPWnjY0xiSdo1ugewZR0VdWbWnbsHCWJZ8ERw7gzrr550m"




def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Prepare API request
    symbol = symbol.upper()
    end = datetime.datetime.now(pytz.timezone("US/Eastern"))
    start = end - datetime.timedelta(days=7)

    # Yahoo Finance API
    url = (
        f"https://query1.finance.yahoo.com/v7/finance/download/{urllib.parse.quote_plus(symbol)}"
        f"?period1={int(start.timestamp())}"
        f"&period2={int(end.timestamp())}"
        f"&interval=1d&events=history&includeAdjustedClose=true"
    )

    # Query API
    try:
        response = requests.get(url, cookies={"session": str(uuid.uuid4())}, headers={"User-Agent": "python-requests", "Accept": "*/*"})
        response.raise_for_status()

        # CSV header: Date,Open,High,Low,Close,Adj Close,Volume
        quotes = list(csv.DictReader(response.content.decode("utf-8").splitlines()))
        quotes.reverse()
        price = round(float(quotes[0]["Adj Close"]), 2)
        return {
            "name": symbol,
            "price": price,
            "symbol": symbol
        }
    except (requests.RequestException, ValueError, KeyError, IndexError):
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"
