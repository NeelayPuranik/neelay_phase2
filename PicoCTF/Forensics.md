# 1. Trivial Flag Transfer Protocol

> Figure out how they moved the [flag](https://mercury.picoctf.net/static/e4836d9bcc740d457f4331d68129a0bc/tftp.pcapng)

## Solution:

- Upon downloading the flag, I found it to have a peculiar extension called .pcapng
- Upon doing some research, I figured out that the file format is a newer generation of an older file format called .pcap
- These files basically store and log the packet traffic of a network, hence why they are called packet capture files
- I found out that these files can be opened using specific software like wireshark.
- I noticed that the the name of the challenge: "Trivial Flag Transfer Protocol" is similar to the name "Trivial File Transfer Protocol" which is a network protocol used to transfer files over the internet.
- I, then, looked at the contents in the given tftp.pcapng file and noticed that a majority of the packets were sent through tftp.
- After some more research, I found a way to extract files transferred through tftp from the .pcapng file by selecting the "tftp" open under "export objects" which is under the "file" menu in wireshark.
- This gave me 6 files out of which 3 of them were pictures, 2 of them appeared to be encrypted text files and the last one was a .deb installer for a program
- I ran the program.deb file in linux and figured out that it was an installer for a tool called steghide
- This tool is used to hide and encrypt data into image and audio files.
- Contextually, I figured out that the challenge probably wanted me to run steghide on the given three images to obtain the flag
- The command I need to use to do so is "steghide extract -sf <img file path>" but then it will prompt me for a key which I still did not have
- I, then, moved onto the text files and ran the instructions.txt file through a cipher identifier which lead me to believe that the text eas encrypted in a ROT13 cipher
- I used a ROT13 decoder to obtain the decrypted text from the file. It said: "TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN"
- This further pointed to the fact that I had to use steghide to extract the flag from the given images
- I then also decoded the plan file using ROT13 to obtain: "IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS"
- This confirmed my suspicions, and I ran steghide on the three images with the keyphrase: "DUEDILIGENCE"
- The first two images did not yield any fruitful results but the third image gave me a flag.txt file
- I then obtained the flag by catting the flag.txt file

## Flag:

```
picoCTF{h1dd3n_1n_pLa1n_51GHT_18375919}
```

## Concepts learnt:

- Learnt about a new file type called pcapng and pcap files
- Learnt how to analyze and extract data from pcapnp and pcap files using tools like wireshark
- Learnt how to use steganography tools like steghide to extract hidden data from image and audio files

## Notes:

- I tried using filters in wireshark to filter out any other protocols other than tftp but that did not seem to work out. Using the export objects tool was the simplest and fastest method to obtain the desired files.

## Resources:

- [pcapng.com](https://pcapng.com/)
- [endace.com - what is a PCAP file?](https://www.endace.com/learn/what-is-a-pcap-file)
- [cloudflare.com - what is a packet](https://www.cloudflare.com/learning/network-layer/what-is-a-packet/)
- [reddit.com - extract tftp file from pcapng](https://www.reddit.com/r/wireshark/comments/6ndvpq/extract_tftp_file_from_pcapng/)
- [steghide.sourceforge.net](https://steghide.sourceforge.net/)
- [dcode.fr - cipher identifier](https://www.dcode.fr/cipher-identifier)
- [dcode.fr - ROT13 decoder](https://www.dcode.fr/rot-13-cipher)

***


# 2. m00nwalk

> Decode this [message](https://jupiter.challenges.picoctf.org/static/fc1edf07742e98a480c6aff7d2546107/message.wav) from the moon.

## Solution:

- I downloaded the given file, it was an audio file with what sounded to be data encoded inside it using beeps
- After some research, I figured out that the file transfer protocol used for sending images of the moon landing from the moon back to the earth was the SSTV (Slow Scan Television) protocol
- This protocol is especially used because it is very efficient at transmitting pictures over narrowband radio frequencies
- I used an online SSTV decoder to obtain the image from the audio file

I have attached the image obtained from the audio file below:

![This image contains the flag written in plain text](assets/decoded_image.png)

## Flag:

```
picoCTF{beep_boop_im_in_space}
```

## Concepts learnt:

- Learnt about a new file transfer protocol called SSTV and why it was chosen for transferring files from the moon landing to the earth

## Notes:

- Nil

## Resources:

- [Online SSTV Decoder by Mathieu Renaud](https://sstv-decoder.mathieurenaud.fr/)

***


# 3. tunn3l v1s10n

> We found this [file](https://mercury.picoctf.net/static/7b2d7c26630e977197022d0af09e3aeb/tunn3l_v1s10n). Recover the flag.

## Solution:

- Initially, I tried running the linux command file on the given file to figure out what type of file it was but that lead no where
- Therefore, I researched upon how to analyze the data inside files and figured out that one can use Hex Editors to do so.
- I, then, downloaded a popular hex editor software called HxD and opened the file inside it
- Below attached is the result I got:

![Hxd Screenshot 1](assets/HxD_SC_1.jpeg)

- After some research, I figured out that the given file is a BMP file. This is so because the rightmost column (Decoded text) starts with BM indicating that it is a BMP file.
- I figured that since windows did not give me an option to open the file in photos, I had to change its extension to .bmp to so do but upon opening up the file in photos, it said that the app does not support this file format.
- Upon taking a closer look, I realised that the BMP header is messed up as the column pairs "0A 0B" and "0E 0F" spelled BA D0 (BAD).
- I figured out what those values should be replaced by, by comparing the BMP fileheader with other BMP fileheaders I obtained online.
- This is the image I obtained upon doing so:

![tunn3l v1s10n V1](assets/tunn3l_v1s10n%20-%201.bmp)

- This led to a decoy flag being obtained
- I noticed that the image seems to have been cropped out and also correlated that with the hint given that the image is not displaying right.
- Therefore, I made several attempts at resizing the image until I finally figured out the correct resolution and obtained the flag
- Below attached is the Image of the final Hex code of the BMP file:

![HxD Screenshot 2](assets/HxD_SC_2.jpeg)

- Below attached is the Image obtained after I correctly resized the picture:

![tunn3l v1s10n V2](assets/tunn3l_v1s10n%20-%202.bmp)

- Therefore, the flag obtained is: picoCTF{qu1t3_a_v13w_2020}

## Flag:

```
picoCTF{qu1t3_a_v13w_2020}
```

## Concepts learnt:

- Learnt how to analyze files at the hex level

## Notes:

- Nil

## Resources:

- [Understanding the BMP file format](https://www.donwalizerjr.com/understanding-bmp/)
- [superuser - How to create a Bitmap image with "pen and paper"?](https://superuser.com/questions/1137140/how-to-create-a-bitmap-image-with-pen-and-paper)

***
