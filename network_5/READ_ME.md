Files

All 30 .pcap files are in the training_data folder, in its respective website's folder

And then each test .pcap is in the test_data folder, one for each website

Collecting Data

I ran sudo timeout 15 tcpdump -w {filename} -s 100 host {guard ip} to get all of the .pcap files

When choosing websites, I wanted each website to be as different as possible, so I can more easily deduce which website is being connected to when examining the packets being relayed.

I chose:

youtube since it is a lot of video content

soundcloud since it is a lot of audio content

reddit since it is a lot of text content

googlemaps since it needs data from user and I assumed required a unique dataflow

slither.io, an interactive game, I knew this required a lot of dynamic graphic rendering, differentiated it from the other sites

lynkapp.co - this is a simple landing page I made for a social app I am making, I knew it would have very little data transferred and thus be able to pick it out by analyzing its .pcap


Stats

In the training_data folder, I have 6 json files to display the .pcap stats, each website has its own file where you can see metric for each individual .pcap file, and then there is a all_website_caps file, that averages the stats from each website's 5 .pcap files. The numbers in this all_website_caps file are what I use to attempt to determine what website is being connected to given a .pcap file in the classify.py program

Classify.py

My classify program is definitely on the more simple side, as I just analyzed the aggregated total packets, outgoing bytes, and median packet size of the sites and created if statements to narrow down so the program can reliably output the correct website given a .pcap file. My rule when creating this conditional classify program was never look at the test data.

First, if the .pcap has less than 100 total packets, the site is most likely my simple landing page lynkapp.co.

If > 100 total packets, I check if there are 0 outgoing bytes, if so, it is either youtube or reddit, if total packets is < 814. it is most likely youtube, if not it is reddit. Since youtube's avg. packets is 247 and reddit's is 1380, just found the middle number.

If > total packets, site is either slither.io, googlemaps, or soundcloud
If median packet size is < 1000, then site is slither.io
Else, if total packets < 932, site is googlemaps, if not, soundcloud. Since googlemaps avg. total packets = 592 and soundcloud = 1272, middle is 932.

This classify program works for every test except soundcloud, as it mistakes this for google maps. 4 out of the 5 soundcloud training pcap's had total packets > 932, which is the threshold, but the test one did not and mistake this for googlemaps. I obviously code have changed this to fit the test file but did not because it ruins the point.

Running Program

You just run program by typing python3 classify.py - and then you will be prompted to enter a website key, which is the website you will be testing

