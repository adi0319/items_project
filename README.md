# Item Catalog

## Project Description
This project was to develop an application that develops a list of items within categories. In order to edit, delete, and/or create new items or categories, the user must be signed in. For users who are not signed in, there are a few views with these CRUD operations disabled. Along with the CRUD operations just explained, there are a few API endpoints that display category and item information in JSON form.

## Prerequisites
- Google OAuth
  Follow the instructions [here](https://developers.google.com/identity/protocols/OAuth2) to obtain OAuth2.0 credentials, client ID and client secret, in order to be able to use Google login for this app.
  - List 'http://localhost:5000' under the section 'Authorized JavaScript origins'
  - List 'http://localhost:5000/login' and 'http://localhost:5000/gconnect' under the section 'Authorized redirect URIs'
  - Download the JSON and save to a file named `client_secrets.json`
  - Place the file in the same directory as `views.py`

- Facebook OAuth
  Visit [this](https://developers.facebook.com) site to register this new app in order to use Facebook login for this app.
  - Go to the 'My Apps' section and create a new app
  - Configure the URL site as: 'http://localhost:5000/'
  - Create a Test Application from the button in the apps dropdown.
  - Don't change the default values.
  - Save the application ID and secret phrase to a file called `fb_client_secrets.json`
  - Place the file in the same directory as `views.py`

## Set Up
1. Install the Linux-based virtual machine. This will require installing [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org/wiki/Download_Old_Builds_5_1)
  - To ensure that the same working environment is used, make sure to use [this vagrantfile](Vagrantfile)
  - After installing or if you simply need to bring the vm back online, use the commands `vagrant up` followed by `vagrant ssh`
2. Navigate to the `/vagrant` directory and clone this project
3. Change directory to the project: `cd items_project`
4. Set up the database by running this command: `python models.py`
5. Run the app: `python views.py`
