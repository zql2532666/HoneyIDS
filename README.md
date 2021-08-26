<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/othneildrew/Best-README-Template">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Best-README-Template</h3>

  <p align="center">
    An awesome README template to jumpstart your projects!
    <br />
    <a href="https://github.com/othneildrew/Best-README-Template"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/othneildrew/Best-README-Template">View Demo</a>
    ·
    <a href="https://github.com/othneildrew/Best-README-Template/issues">Report Bug</a>
    ·
    <a href="https://github.com/othneildrew/Best-README-Template/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

HoneyIDS is an internal attack and intrusion detection framework that makes use of distributed honeypot nodes. It meshes honeypots, a deception-based technology, with a traditional open-source NIDS to tackle network intrusion detection in a distinctive way. 

### Features

* Streamlined deployment mechanism for easy honey nodes deployment
* Full stack web gui for easy management and pleasant user experience 
* Real-time log collection
* Data correlation to help the user get a high-level abstracted view of the attacks happening inside the network ecosystem
* Real-time status monitoring of honey nodes deployed    

### System Architecture
<p align="center">
  <img src="img/arch.png" alt="" width="80%" height="80%">  
</p>



### Built With

The following technologies are used in this project:

* [Flask](https://flask.palletsprojects.com)
* [MySQL](https://www.mysql.com)
* [Hp-Feeds](https://hpfeeds.org/)
* [Snort](https://www.snort.org/)

Open source honeypots used:

* [Cowrie](https://github.com/cowrie/cowrie)
* [Dionaea](https://github.com/DinoTools/dionaea)
* [Shockpot](https://github.com/pwnlandia/shockpot)
* [Drupot](https://github.com/d1str0/drupot)
* [Elastichoney](https://github.com/jordan-wright/elastichoney)
* [Sticky Elephant](https://github.com/betheroot/sticky_elephant)
* [Wordpot](https://github.com/gbrindisi/wordpot)

Frontend template used:

* [AdminLTE](https://github.com/ColorlibHQ/AdminLTE)


<!-- GETTING STARTED -->
## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.
* npm
  ```sh
  npm install npm@latest -g
  ```

### Installation

1. Get a free API Key at [https://example.com](https://example.com)
2. Clone the repo
   ```sh
   git clone https://github.com/your_username_/Project-Name.git
   ```
3. Install NPM packages
   ```sh
   npm install
   ```
4. Enter your API in `config.js`
   ```JS
   const API_KEY = 'ENTER YOUR API';
   ```



<!-- USAGE EXAMPLES -->
## Usage
#### Login
Users can sign in to the HoneyIDS web applications using the following default credentials:

| Username | Password |
|----------|----------|
| admin_1  | admin    |
| admin_2  | admin    | 

#### Dashboard 


#### Data Correlation
https://user-images.githubusercontent.com/29125030/125169393-86780780-e1dc-11eb-99e8-9ddcf48030e6.mp4


#### Deployment 

https://user-images.githubusercontent.com/29125030/125169432-b6270f80-e1dc-11eb-8abe-2bf3988fb47a.mp4


#### Nodes


#### Logs

https://user-images.githubusercontent.com/29125030/125169454-c9d27600-e1dc-11eb-8257-acee1f266012.mp4





<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/othneildrew/Best-README-Template/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- CONTACT -->
## Contact

zql2532666 - zql2532666@gmail.com

Project Link: [https://github.com/zql2532666/HoneyIDS](https://github.com/zql2532666/HoneyIDS)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [Cowrie](https://github.com/cowrie/cowrie)
* [Dionaea](https://github.com/DinoTools/dionaea)
* [Shockpot](https://github.com/pwnlandia/shockpot)
* [Drupot](https://github.com/d1str0/drupot)
* [Elastichoney](https://github.com/jordan-wright/elastichoney)
* [Sticky Elephant](https://github.com/betheroot/sticky_elephant)
* [Wordpot](https://github.com/gbrindisi/wordpot)
* [AdminLTE](https://github.com/ColorlibHQ/AdminLTE)
