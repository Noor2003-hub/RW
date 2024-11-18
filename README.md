# SmartFan
#### Video Demo:  <https://www.youtube.com/watch?v=BV3OMB2SrrM&t=1s>
#### Description:
## Code Features:
- [Flask](https://flask.palletsprojects.com/en/1.1.x/)
- [Spotify API](https://developer.spotify.com/documentation/web-api)
- Python
- HTML
- CSS
- SQL

## How Code Works:
SmartFan is memory game that asks players to remember the song titles of artists they have chosen,
so the game goes like this:
- choosing the artists that you can memorize their song titles.
- game starts. by choosing random artists from your favorite ones, and random letter that can start song title for this artist.
- if you got the right answer you pass this round with more 50 points, but if you skip the game (your score should be higher than 25 to do so) you will pass this round with loss of 25 points.

## explaning each page in the project:
### database:
it have the data of each user:
- user ID
- user name
- user hash of password
- current score
- highest score achived

## Making Account:
- username: should be unique (not taken)
- password: should include letters, numbers and special characters


## Index Page:
Shows the highest score achived, and have the start new game button
<p><img src="Screenshots/img1.png" width = "500"></p>

## New Page:
after you click {Start New Game button} you will get the new page.
<br><br>Setting up the game before playing, by making list of the artist(s) will appear later in the game (randomly appearance).
<br>write the artist name in the search bar, then click add to add them to the game,
<br>its okay to misspell the artist, it will get the most name that matches the input.</p>
<p><img src="Screenshots/giff.gif" width = "500"></p>
also you can clear the list you made of artists names by {clear all button}
<br>and start new list
<p><img src="Screenshots/gif2.gif" width = "500"></p>

## Game Page:
after sucessfully adding the desired artists names and clicking {Ready button} you will get game page.
<br><br>random artist (from the list you made in new page) will appear,
<br> next to them will apear random letter that could be the start of song title for that artist (letter that never appered  before),
<br> you should know the title of this song and write it in the input bar.
| Wrong answer | Right answer |
| :---: | :---: |
| <img src="Screenshots/gif3.gif" width="400">  | <img src="Screenshots/gif4.gif" width="400">|

or you can skip the round if you found it hard to get the answer (costs 25 point from your score)
<br>in this case it will choose random artist and random letter
<p><img src="Screenshots/gif5.gif" width = "400"></p>

## Correct Page:
simply this page appear when you get the right answer, you can misspell the song title and still win,
<br>this page reveals the correct answer (track title/artists/release date)
<br>and you will get 50 points. then you can click next to get the next round of the game.

## Finish Page:
after you finish all possible letters that can start title of song for the whole artists list, you will finsih the game
<p><img src="Screenshots/img3.png" width = "400"></p>

## About Page:
will help you understand the rules of the game.



