# media_hoster

a small project I made in 2022 for my friends.

it automatically encoded images and files to be below 8 megabytes (now updated to 20), for discord embeds.

the automatic encoding is pretty janky and ffmpeg refuses to listen to my bitrate settings, so it's hit or miss whether or not it encodes with the right size or not.

now that invisible links have been patched, I don't see a good reason to be using custom hosters at all, past funny domains. therefore, I will release this project now as it is of no use to me.

the interesting encoding logic is in [util.rs](src/util.rs).

![main page](https://i.imgur.com/QSuzLaI.png)
