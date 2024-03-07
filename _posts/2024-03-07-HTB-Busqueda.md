---
layout: post
title: HTB-Busqueda
published: true
---
# Busqueda machine on [hackthebox](https://app.hackthebox.com/)


## Enumeration:


nmap scan:
```
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-11 03:38 EDT
Nmap scan report for 10.10.11.208
Host is up (0.081s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

We will add the hostname "searcher.htb" to /etc/hosts:

`echo "10.10.11.208    searcher.htb" | sudo tee -a /etc/hosts`



The website:

![](../assets/images/busqueda/20231011104137.png)

The website uses an open source package called "searchor", with 2.4.0 version, after searching and reading about it we can find a vulnerability in it, that allows us to execute code, so we can get a shell.


## Exploitation:

The exploit on GitHub:[Link.](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection)

Highly recommended to check it.

After we run the code like this:
![](../assets/images/busqueda/20231011105302.png)


Let's check our listener:

![](../assets/images/busqueda/20231011105330.png)

We got a shell!!

And easy user:

![](../assets/images/busqueda/20231011105411.png)

Now since we have a user let's generate ssh keys to access the system with a better shell.

On our local system:
![](../assets/images/busqueda/20231011110740.png)

We are going to generate public and private key.
note: key is the name of the file outputed.

![](../assets/images/busqueda/20231011110841.png)

NOTE: it's important to change the "user@host" at the end of public key file.

after that we will copy our public key and put it in the target user directory at .ssh/authorized_keys file.

On our target machine:
```bash
echo "the public key text" >> .ssh/authorized_kyes
```


Then we will do this on our machine:

```bash
ssh -i key svc@10.10.11.208
```

And now we have a ssh session, time for enumeration for root.

In the directory that has the website, we see that its a git repo, so let's check the config file:

![](../assets/images/busqueda/20231011124658.png)
We see that there is a password, and there is a gitea subdomain running, let's first check if the password is for svc using sudo -l:

![](../assets/images/busqueda/20231011124822.png)
And it is....

Now let's add the gitea instance to /etc/hosts and check it:

![](../assets/images/busqueda/20231011124948.png)
We have a gitea instance running (which if you dont know its a service used for private hosting of repositories).

Let's try to login with the credentials we found earlier:
![](../assets/images/busqueda/20231011130412.png)

We can see that we have a repository with the web app, and there is a user called administrator, but upon trying to login to it with the same password, we fail...

So when we try to execute the script we were able to do with sudo, we can provide some arguments to it.

![](../assets/images/busqueda/20231011125152.png)

Also we can inspect certain containers, but when we do so we see that we need a format, googling about it really quick show us different formats and things we can see about a docker container.

![](../assets/images/busqueda/20231011125738.png)

So we will do the following:

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' 9608
```

NOTE: 9608 is the ID of the gitea container.

![](../assets/images/busqueda/20231011125840.png)

Let's echo this locally and check pipe it to "jq" to be easier to read:

![](../assets/images/busqueda/20231011130003.png)

Here we can see we have another password, could this be for administrator?

![](../assets/images/busqueda/20231011130540.png)

And it is!!

We have a couple of scripts code in here, so let's check them.


In one of the scripts, specifically "system checkup" we can see that when we execute it, it does call for a bash file in the current directory (where we execute the script) and it execute it, since we can run it with sudo, we can make a "custom" full-checkup.sh, and embed a reverse shell in it..

So we do the following:
![](../assets/images/busqueda/20231011131055.png)

Making a script file and putting a reverse shell in it, then now let's execute the full-chekup as sudo:

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

Now checking our listener we can see we have root:

![](../assets/images/busqueda/20231011131525.png)


And done machine....

thanks for reading!

Happy hacking!! :)

