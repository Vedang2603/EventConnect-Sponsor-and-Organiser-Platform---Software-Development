CREATE DATABASE se_project;
USE se_project;

-- Create Organization Table
CREATE TABLE Organization (
    OrganizationID INT AUTO_INCREMENT PRIMARY KEY,
    Name VARCHAR(255) NOT NULL,
    ContactInformation VARCHAR(255) NOT NULL,
    Description TEXT,
    Location VARCHAR(255) NOT NULL,
    logo LONGBLOB
);

-- Create User Table
CREATE TABLE User (
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    Name VARCHAR(255) NOT NULL,
    Email VARCHAR(255) UNIQUE NOT NULL,
    Role ENUM('sponsor', 'organiser') NOT NULL,
    Password VARCHAR(255) NOT NULL,
    OrganizationID INT,
    profile_pic LONGBLOB,
    FOREIGN KEY (OrganizationID) REFERENCES Organization(OrganizationID)
);

-- Create Event Table (first, so it can be referenced later)
CREATE TABLE Event (
    EventID INT AUTO_INCREMENT PRIMARY KEY,
    Title VARCHAR(255) NOT NULL,
    Location VARCHAR(255) NOT NULL,
    footfall INT NOT NULL,
    popularity_factor TEXT,
    Description TEXT,
    EventDate TIMESTAMP,
    CreatedAtDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    Status VARCHAR(20) DEFAULT 'scheduled',
    Topic ENUM(
        "music", "business", "food_drink", "community_culture", 
        "performing_visual_arts", "film_media_entertainment", 
        "sports_fitness", "health_wellness", "science_technology", 
        "travel_outdoor", "charity_causes", "religion_spirituality", 
        "family_education", "seasonal_holiday", "government_politics", 
        "fashion_beauty", "home_lifestyle", "auto_boat_air", 
        "hobbies_special_interests"
    ) NOT NULL,
    OrganizerID INT,
    PackageID INT,
    EventType ENUM(
        'conference', 'seminar', 'workshop', 'cultural', 'sports', 
        'concert', 'fashion show'
    ) DEFAULT 'concert',
    FOREIGN KEY (OrganizerID) REFERENCES User(UserID) ON DELETE CASCADE
);

-- Now create Package Table
CREATE TABLE Package (
    PackageID INT AUTO_INCREMENT PRIMARY KEY,
    OrganizerID INT,
    Name VARCHAR(255) NOT NULL,
    Price DECIMAL(10,2) NOT NULL,
    Price_limit DECIMAL(10,2) NOT NULL,
    Description TEXT,
    EventID INT,
    FOREIGN KEY (OrganizerID) REFERENCES User(UserID) ON DELETE CASCADE,
    FOREIGN KEY (EventID) REFERENCES Event(EventID) ON DELETE CASCADE
);

-- Continue with the rest of the tables
-- Create Interest Table
CREATE TABLE Interest (
    interactionID INT AUTO_INCREMENT PRIMARY KEY,
    SponsorID INT NOT NULL,
    OrganizerID INT NOT NULL,
    interaction_type VARCHAR(50) NOT NULL,
    interaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    accepted BOOLEAN,
    PackageID INT NOT NULL,
    FOREIGN KEY (PackageID) REFERENCES Package(PackageID) ON DELETE CASCADE
);

-- Create Interaction Table
CREATE TABLE Interaction (
    chatbox_id INT AUTO_INCREMENT PRIMARY KEY,
    sponsor_id INT,
    organiser_id INT,
    package_id INT,
    FOREIGN KEY (sponsor_id) REFERENCES User(UserID) ON DELETE CASCADE,
    FOREIGN KEY (organiser_id) REFERENCES User(UserID) ON DELETE CASCADE,
    FOREIGN KEY (package_id) REFERENCES Package(PackageID) ON DELETE CASCADE
);

-- Create Chatbox Table
CREATE TABLE Chatbox (
    msg_id INT AUTO_INCREMENT PRIMARY KEY,
    box_id INT NOT NULL,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (box_id) REFERENCES Interaction(chatbox_id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES User(UserID),
    FOREIGN KEY (receiver_id) REFERENCES User(UserID)
);

-- Create Feedback Table
CREATE TABLE Feedback (
    feedback_id INT AUTO_INCREMENT PRIMARY KEY,
    organiser_id INT NOT NULL,
    sponsor_id INT NOT NULL,
    event_id INT NOT NULL,
    rating INT,
    sponsorship_exhibitors VARCHAR(255),
    experienced_footfall VARCHAR(255),
    overall_satisfaction VARCHAR(255),
    communication VARCHAR(255),
    organization VARCHAR(255),
    venue VARCHAR(255),
    logistics VARCHAR(255),
    catering_food VARCHAR(255),
    technology_equipment VARCHAR(255),
    sustainability VARCHAR(255),
    comments TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organiser_id) REFERENCES User(UserID),
    FOREIGN KEY (sponsor_id) REFERENCES User(UserID),
    FOREIGN KEY (event_id) REFERENCES Event(EventID)
);
