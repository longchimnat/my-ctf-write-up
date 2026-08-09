# Day 0: The Brochure
## Description
![alt text](image.png)

- Link challenge: https://tryhackme.com/room/hh-thebrochure-081f3e36

**File provided** : thebrochure.png

## Analysis
- When you download the file you can see the .png, open that then you will see this
![c:\Users\Lecoo\Downloads\attachments-1784426010065\thebrochure.png](thebrochure.png)

## Solution
- So we head to the instagram and use search to find Byte lotus Resorts
![](image-1.png)

- Click the following, you will see the account Vera
![alt text](image-3.png)

- As you can see that 3 pictures have message encoded into base64
- Let mix this
```base64
VEhNe1YzckBzX2FDQzB1bnRfaDRzX2IzM25fZjB1bmQhfQ==
```

Decode then we get the flag

```success
THM{V3r@s_aCC0unt_h4s_b33n_f0und!}
```