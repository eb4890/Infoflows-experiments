import os
import json
from functools import wraps
from flask import Flask, request, render_template, jsonify, redirect, url_for, session
import google.generativeai as genai
from google.cloud import firestore
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default-secret-key-for-development")

# Configuration
CLIENT_SECRETS_FILE = "client_secret.json"  # Download from Google Cloud Console
SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 
          'https://www.googleapis.com/auth/userinfo.profile']
API_SERVICE_NAME = 'oauth2'
API_VERSION = 'v2'

# Set up Google Gemini API
api_key = os.environ.get("GOOGLE_API_KEY")
genai.configure(api_key=api_key)

# Initialize Firestore DB
db = firestore.Client()

# Sample user database (for development only - real users will be stored in Firestore)
sample_users = [
    {
        "id": "user001",
        "name": "Sarah Johnson",
        "interests": ["urban gardening", "beekeeping", "renewable energy"],
        "location": "Clifton, Bristol",
        "activity_level": "high",
        "communication_preferences": "immediate",
    },
    {
        "id": "user002",
        "name": "James Wilson",
        "interests": ["waste reduction", "community cycling", "solar panels"],
        "location": "Bedminster, Bristol",
        "activity_level": "medium",
        "communication_preferences": "digest",
    },
    {
        "id": "user003",
        "name": "Amira Patel",
        "interests": ["sustainable food", "composting", "wildlife conservation"],
        "location": "Easton, Bristol",
        "activity_level": "low",
        "communication_preferences": "immediate",
    },
    {
        "id": "user004",
        "name": "David Chen",
        "interests": ["electric vehicles", "renewable energy", "policy advocacy"],
        "location": "Redland, Bristol",
        "activity_level": "medium",
        "communication_preferences": "digest",
    },
    {
        "id": "user005",
        "name": "Emma Lewis",
        "interests": ["community gardening", "zero waste", "rainwater harvesting"],
        "location": "Southville, Bristol",
        "activity_level": "high",
        "communication_preferences": "immediate",
    },
]

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'credentials' not in session:
            return redirect(url_for('authorize'))
        return f(*args, **kwargs)
    return decorated_function

# Routes for authentication
@app.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = url_for('oauth2callback', _external=True)
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    session['state'] = state

    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback
    state = session['state']
    
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    # Get user info
    user_info = get_user_info()
    
    # Store basic user info in session
    session['user_email'] = user_info.get('email')
    session['user_name'] = user_info.get('name')
    
    # Check if user exists in Firestore, create if not
    save_user_to_firestore(user_info)
    
    return redirect(url_for('dashboard'))

def get_user_info():
    """Get user info from Google API"""
    if 'credentials' not in session:
        return None

    # Load credentials from the session
    credentials = google.oauth2.credentials.Credentials(**session['credentials'])
    
    # Build the service
    service = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)
    
    # Call the API
    user_info = service.userinfo().get().execute()
    
    # Update session credentials (in case they were refreshed)
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    
    return user_info

def save_user_to_firestore(user_info):
    """Save user to Firestore if they don't exist yet"""
    if not user_info:
        return
    
    email = user_info.get('email')
    if not email:
        return
    
    # Create a reference to the user document
    user_ref = db.collection('users').document(email)
    
    # Check if user exists
    if not user_ref.get().exists:
        # Create new user
        user_data = {
            'email': email,
            'name': user_info.get('name', ''),
            'picture': user_info.get('picture', ''),
            'created_at': firestore.SERVER_TIMESTAMP,
            # Add default values for targeting
            'interests': [],
            'location': '',
            'activity_level': 'medium',
            'communication_preferences': 'immediate',
        }
        user_ref.set(user_data)

def get_user_prompts(email):
    """Get user's saved prompts from Firestore"""
    if not email:
        return []
    
    prompts_ref = db.collection('users').document(email).collection('prompts')
    prompts = []
    
    for doc in prompts_ref.stream():
        prompt_data = doc.to_dict()
        prompt_data['id'] = doc.id
        prompts.append(prompt_data)
    
    return prompts

def save_user_prompt(email, prompt_text, prompt_name="My Prompt"):
    """Save a user prompt to Firestore"""
    if not email or not prompt_text:
        return None
    
    prompt_data = {
        'name': prompt_name,
        'text': prompt_text,
        'created_at': firestore.SERVER_TIMESTAMP
    }
    
    # Add to prompts subcollection
    prompt_ref = db.collection('users').document(email).collection('prompts').document()
    prompt_ref.set(prompt_data)
    
    return prompt_ref.id

def get_all_users_from_firestore():
    """Get all users from Firestore for targeting"""
    users_ref = db.collection('users')
    users = []
    
    for doc in users_ref.stream():
        user_data = doc.to_dict()
        user_data['id'] = doc.id  # Use email as ID
        users.append(user_data)
    
    return users if users else sample_users  # Fall back to sample users if none in DB

def create_gemini_prompt(message, project_details, users):
    """Create a prompt for Gemini to determine message recipients."""
    prompt = f"""
    You are a message targeting system for Bristol green projects. 
    Your task is to analyze the message and project details below, and decide which users should receive this information.
    
    MESSAGE:
    {message}
    
    PROJECT DETAILS:
    {project_details}
    
    USERS:
    {json.dumps(users, indent=2)}
    
    For each user, determine if they should receive this message based on:
    1. Relevance of the message to their interests
    2. Geographic proximity within Bristol
    3. Their communication preferences
    4. Their activity level
    
    Assign each user one of the following codes:
    - 0: Don't send (message is not relevant enough)
    - 1: Send immediately (highly relevant and matches their preference for immediate updates)
    - 2: Include in digest (relevant but better suited for digest based on preferences or lower urgency)
    
    Return your response in this exact JSON format with no additional text:
    {{
      "targeting_rationale": "Brief explanation of your overall targeting strategy",
      "user_targeting": [
        {{"user_id": "user001", "code": 1, "reason": "Brief reason"}},
        {{"user_id": "user002", "code": 2, "reason": "Brief reason"}},
        ... and so on for each user
      ]
    }}
    """
    return prompt

def get_targeting_recommendations(message, project_details):
    """Get targeting recommendations from Gemini."""
    model = genai.GenerativeModel('gemini-pro')
    
    # Get users from Firestore
    users = get_all_users_from_firestore()
    
    prompt = create_gemini_prompt(message, project_details, users)
    
    response = model.generate_content(prompt)
    try:
        # Parse the JSON response
        result = json.loads(response.text)
        return result
    except json.JSONDecodeError:
        # If Gemini doesn't return valid JSON, extract it from the text
        import re
        json_match = re.search(r'({.*})', response.text.replace('\n', ''), re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except:
                return {"error": "Failed to parse response"}
        return {"error": "Failed to get valid targeting data"}

# Main routes
@app.route('/')
def home():
    if 'credentials' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_email = session.get('user_email')
    user_name = session.get('user_name', 'User')
    
    # Get user's saved prompts
    prompts = get_user_prompts(user_email)
    
    return render_template('dashboard.html', user_name=user_name, prompts=prompts)

@app.route('/target', methods=['POST'])
@login_required
def target_message():
    message = request.form.get('message', '')
    project_details = request.form.get('project_details', '')
    save_prompt = request.form.get('save_prompt', 'false') == 'true'
    prompt_name = request.form.get('prompt_name', 'My Prompt')
    
    if not message or not project_details:
        return jsonify({"error": "Message and project details are required"})
    
    # Save prompt if requested
    if save_prompt:
        user_email = session.get('user_email')
        save_user_prompt(user_email, message, prompt_name)
    
    targeting_result = get_targeting_recommendations(message, project_details)
    return jsonify(targeting_result)

@app.route('/prompts', methods=['GET'])
@login_required
def list_prompts():
    user_email = session.get('user_email')
    prompts = get_user_prompts(user_email)
    return jsonify(prompts)

@app.route('/prompts/<prompt_id>', methods=['GET'])
@login_required
def get_prompt(prompt_id):
    user_email = session.get('user_email')
    prompt_ref = db.collection('users').document(user_email).collection('prompts').document(prompt_id)
    prompt = prompt_ref.get()
    
    if prompt.exists:
        data = prompt.to_dict()
        data['id'] = prompt_id
        return jsonify(data)
    else:
        return jsonify({"error": "Prompt not found"}), 404

@app.route('/prompts', methods=['POST'])
@login_required
def create_prompt():
    user_email = session.get('user_email')
    data = request.get_json()
    
    if not data or 'text' not in data:
        return jsonify({"error": "Prompt text is required"}), 400
    
    prompt_name = data.get('name', 'My Prompt')
    prompt_text = data.get('text')
    
    prompt_id = save_user_prompt(user_email, prompt_text, prompt_name)
    
    if prompt_id:
        return jsonify({"id": prompt_id, "name": prompt_name, "text": prompt_text})
    else:
        return jsonify({"error": "Failed to save prompt"}), 500

@app.route('/prompts/<prompt_id>', methods=['DELETE'])
@login_required
def delete_prompt(prompt_id):
    user_email = session.get('user_email')
    db.collection('users').document(user_email).collection('prompts').document(prompt_id).delete()
    return jsonify({"success": True})

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    user_email = session.get('user_email')
    data = request.get_json()
    
    # Update user profile in Firestore
    user_ref = db.collection('users').document(user_email)
    
    # Only update fields that are provided
    update_data = {}
    if 'interests' in data:
        update_data['interests'] = data['interests']
    if 'location' in data:
        update_data['location'] = data['location']
    if 'activity_level' in data:
        update_data['activity_level'] = data['activity_level']
    if 'communication_preferences' in data:
        update_data['communication_preferences'] = data['communication_preferences']
    
    if update_data:
        user_ref.update(update_data)
        return jsonify({"success": True})
    else:
        return jsonify({"error": "No fields to update"}), 400

# Templates
@app.route('/templates/login.html')
def login_template():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bristol Green Projects - Login</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                max-width: 800px; 
                margin: 0 auto; 
                padding: 20px;
                text-align: center;
            }
            .login-container {
                margin-top: 100px;
            }
            h1 { 
                color: #2E7D32;
            }
            .btn {
                background-color: #4CAF50;
                color: white;
                padding: 12px 20px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 16px;
                margin-top: 20px;
            }
            .description {
                margin: 30px 0;
                text-align: left;
                line-height: 1.5;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>Bristol Green Projects</h1>
            <p>Connect with sustainability initiatives in your community</p>
            
            <div class="description">
                <p>This platform helps connect Bristol residents with local green projects that match their interests. 
                Project organizers can target their messages to the most relevant audience, helping to build a more 
                sustainable Bristol community.</p>
            </div>
            
            <a href="/authorize" class="btn">Login with Google</a>
        </div>
    </body>
    </html>
    """

@app.route('/templates/dashboard.html')
def dashboard_template():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bristol Green Projects - Dashboard</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                max-width: 1000px; 
                margin: 0 auto; 
                padding: 20px;
            }
            header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                border-bottom: 1px solid #ddd;
                padding-bottom: 10px;
            }
            .logout {
                color: #777;
                text-decoration: none;
            }
            .logout:hover {
                text-decoration: underline;
            }
            .container {
                display: flex;
                gap: 20px;
            }
            .messaging {
                flex: 2;
                padding-right: 20px;
            }
            .sidebar {
                flex: 1;
                border-left: 1px solid #ddd;
                padding-left: 20px;
            }
            .form-group { 
                margin-bottom: 15px; 
            }
            label { 
                display: block; 
                margin-bottom: 5px; 
                font-weight: bold; 
            }
            input[type="text"], textarea { 
                width: 100%; 
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            textarea { 
                height: 100px; 
            }
            button { 
                background-color: #4CAF50; 
                color: white; 
                padding: 10px 15px; 
                border: none; 
                border-radius: 4px;
                cursor: pointer; 
            }
            button:hover {
                background-color: #3e8e41;
            }
            .results { 
                margin-top: 20px; 
            }
            table { 
                width: 100%; 
                border-collapse: collapse; 
            }
            th, td { 
                border: 1px solid #ddd; 
                padding: 8px; 
                text-align: left; 
            }
            th { 
                background-color: #f2f2f2; 
            }
            .code-0 { 
                background-color: #ffcccc; 
            }
            .code-1 { 
                background-color: #ccffcc; 
            }
            .code-2 { 
                background-color: #ffffcc; 
            }
            .prompt-list {
                margin-top: 20px;
            }
            .prompt-item {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
                margin-bottom: 10px;
                cursor: pointer;
            }
            .prompt-item:hover {
                background-color: #f9f9f9;
            }
            .save-prompt-container {
                margin-top: 10px;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
                background-color: #f9f9f9;
            }
            .tabs {
                display: flex;
                margin-bottom: 15px;
                border-bottom: 1px solid #ddd;
            }
            .tab {
                padding: 10px 15px;
                cursor: pointer;
                border: 1px solid transparent;
            }
            .tab.active {
                border: 1px solid #ddd;
                border-bottom: 1px solid white;
                border-radius: 4px 4px 0 0;
                margin-bottom: -1px;
            }
            .tab-content {
                display: none;
            }
            .tab-content.active {
                display: block;
            }
        </style>
    </head>
    <body>
        <header>
            <h1>Bristol Green Projects</h1>
            <div>
                Welcome, <span id="user-name">{{ user_name }}</span> | 
                <a href="/logout" class="logout">Logout</a>
            </div>
        </header>
        
        <div class="container">
            <div class="messaging">
                <div class="tabs">
                    <div class="tab active" data-tab="messaging">Message Targeting</div>
                    <div class="tab" data-tab="profile">My Profile</div>
                </div>
                
                <div id="messaging-tab" class="tab-content active">
                    <h2>Target Your Message</h2>
                    
                    <div class="form-group">
                        <label for="message">Message Content:</label>
                        <textarea id="message" placeholder="Enter the message you want to send..."></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="project_details">Project Details:</label>
                        <textarea id="project_details" placeholder="Enter details about the project (location, timing, requirements, etc.)..."></textarea>
                    </div>
                    
                    <div class="form-group save-prompt-container">
                        <input type="checkbox" id="save_prompt" />
                        <label for="save_prompt" style="display: inline;">Save this message as a prompt template</label>
                        <div id="prompt_name_container" style="display: none; margin-top: 10px;">
                            <label for="prompt_name">Prompt Name:</label>
                            <input type="text" id="prompt_name" placeholder="Enter a name for this prompt" />
                        </div>
                    </div>
                    
                    <button onclick="targetMessage()">Determine Recipients</button>
                    
                    <div id="results" class="results" style="display: none;">
                        <h2>Targeting Results</h2>
                        <p id="rationale"></p>
                        
                        <table id="targeting-table">
                            <thead>
                                <tr>
                                    <th>User ID</th>
                                    <th>Name</th>
                                    <th>Decision</th>
                                    <th>Reason</th>
                                </tr>
                            </thead>
                            <tbody id="targeting-results"></tbody>
                        </table>
                    </div>
                </div>
                
                <div id="profile-tab" class="tab-content">
                    <h2>My Profile</h2>
                    <p>Update your interests and preferences to receive relevant green project notifications.</p>
                    
                    <div class="form-group">
                        <label for="interests">Interests (comma-separated):</label>
                        <input type="text" id="interests" placeholder="e.g., urban gardening, beekeeping, renewable energy" />
                    </div>
                    
                    <div class="form-group">
                        <label for="location">Bristol Neighborhood:</label>
                        <input type="text" id="location" placeholder="e.g., Clifton, Bedminster, Easton" />
                    </div>
                    
                    <div class="form-group">
                        <label for="activity_level">Activity Level:</label>
                        <select id="activity_level">
                            <option value="high">High - Very active, want to be involved in many projects</option>
                            <option value="medium" selected>Medium - Moderately active, selective about projects</option>
                            <option value="low">Low - Occasionally active, minimal involvement</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="communication_preferences">Communication Preferences:</label>
                        <select id="communication_preferences">
                            <option value="immediate" selected>Immediate - Send me updates as they happen</option>
                            <option value="digest">Digest - Collect updates and send periodically</option>
                        </select>
                    </div>
                    
                    <button onclick="updateProfile()">Save Profile</button>
                    <div id="profile-status" style="margin-top: 10px; display: none;"></div>
                </div>
            </div>
            
            <div class="sidebar">
                <h2>My Saved Prompts</h2>
                <p>Click on a prompt to load it into the message field.</p>
                
                <div id="prompt-list" class="prompt-list">
                    {% if prompts %}
                        {% for prompt in prompts %}
                            <div class="prompt-item" data-text="{{ prompt.text }}" onclick="loadPrompt('{{ prompt.text }}')">
                                <strong>{{ prompt.name }}</strong>
                            </div>
                        {% endfor %}
                    {% else %}
                        <p>No saved prompts yet. Save a message to add it here.</p>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <script>
            // Tab functionality
            document.querySelectorAll('.tab').forEach(tab => {
                tab.addEventListener('click', () => {
                    // Remove active class from all tabs
                    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
                    
                    // Add active class to clicked tab and corresponding content
                    tab.classList.add('active');
                    document.getElementById(tab.dataset.tab + '-tab').classList.add('active');
                });
            });
            
            // Show/hide prompt name field
            document.getElementById('save_prompt').addEventListener('change', function() {
                document.getElementById('prompt_name_container').style.display = 
                    this.checked ? 'block' : 'none';
            });
            
            // Load profile data on page load
            window.addEventListener('DOMContentLoaded', async () => {
                try {
                    const response = await fetch('/prompts');
                    const prompts = await response.json();
                    
                    const promptList = document.getElementById('prompt-list');
                    if (prompts && prompts.length > 0) {
                        promptList.innerHTML = prompts.map(prompt => `
                            <div class="prompt-item" onclick="loadPrompt(${JSON.stringify(prompt.text)})">
                                <strong>${prompt.name}</strong>
                                <span class="delete-prompt" onclick="deletePrompt('${prompt.id}', event)">🗑️</span>
                            </div>
                        `).join('');
                    } else {
                        promptList.innerHTML = '<p>No saved prompts yet. Save a message to add it here.</p>';
                    }
                } catch (error) {
                    console.error('Error loading prompts:', error);
                }
            });
            
            function loadPrompt(text) {
                document.getElementById('message').value = text;
            }
            
            function deletePrompt(id, event) {
                event.stopPropagation();
                if (confirm('Are you sure you want to delete this prompt?')) {
                    fetch(`/prompts/${id}`, {
                        method: 'DELETE'
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            // Remove the prompt item from the DOM
                            event.target.parentElement.remove();
                        }
                    })
                    .catch(error => {
                        console.error('Error deleting prompt:', error);
                    });
                }
            }
            
            function updateProfile() {
                const interests = document.getElementById('interests').value.split(',').map(i => i.trim()).filter(i => i);
                const location = document.getElementById('location').value.trim();
                const activityLevel = document.getElementById('activity_level').value;
                const communicationPreferences = document.getElementById('communication_preferences').value;
                
                fetch('/update-profile', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        interests,
                        location,
                        activity_level: activityLevel,
                        communication_preferences: communicationPreferences
                    })
                })
                .then(response => response.json())
                .then(data => {
                    const statusEl = document.getElementById('profile-status');
                    if (data.success) {
                        statusEl.textContent = 'Profile updated successfully!';
                        statusEl.style.color = 'green';
                    } else {
                        statusEl.textContent = 'Error updating profile: ' + (data.error || 'Unknown error');
                        statusEl.style.color = 'red';
                    }
                    statusEl.style.display = 'block';
                    setTimeout(() => {
                        statusEl.style.display = 'none';
                    }, 3000);
                })
                .catch(error => {
                    console.error('Error updating profile:', error);
                    const statusEl = document.getElementById('profile-status');
                    statusEl.textContent = 'Error updating profile. Please try again.';
                    statusEl.style.color = 'red';
                    statusEl.style.display = 'block';
                });
            }
            
            function targetMessage() {
                const message = document.getElementById('message').value;
                const projectDetails = document.getElementById('project_details').value;
                const savePrompt = document.getElementById('save_prompt').checked;
                const promptName = document.getElementById('prompt_name').value || 'My Prompt';
                
                if (!message || !projectDetails) {
                    alert('Please enter both message and project details');
                    return;
                }
                
                // Show loading state
                document.getElementById('results').style.display = 'block';
                document.getElementById('targeting-results').innerHTML = '<tr><td colspan="4">Processing...</td></tr>';
                
                // Send request to backend
                fetch('/target', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: new URLSearchParams({
                        'message': message,
                        'project_details': projectDetails,
                        'save_prompt': savePrompt,
                        'prompt_name': promptName
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Error: ' + data.error);
                        return;
                    }
                    
                    // Display rationale
                    document.getElementById('rationale').textContent = data.targeting_rationale;
                    
                    // Display user targeting
                    const tableBody