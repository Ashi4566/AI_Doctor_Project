from flask import Flask, request, render_template, jsonify, redirect, url_for, session, g, flash, abort
import numpy as np
import pandas as pd
import pickle
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os


# flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production
DATABASE = 'users.db'
ADMIN_EMAIL = 'admin@yourdomain.com'


# load databasedataset===================================
sym_des = pd.read_csv("data/symtoms_df.csv")
precautions = pd.read_csv("data/precautions_df.csv")
workout = pd.read_csv("data/workout_df.csv")
description = pd.read_csv("data/description.csv")
medications = pd.read_csv('data/medications.csv')
diets = pd.read_csv("data/diets.csv")


# load model===========================================
svc = pickle.load(open('svc.pkl','rb'))


#============================================================
# custome and helping functions
#==========================helper funtions================
def helper(dis):
    try:
        # Get description
        desc = description[description['Disease'] == dis]['Description']
        desc = " ".join([w for w in desc]) if not desc.empty else "Description not available"

        # Get precautions
        pre = precautions[precautions['Disease'] == dis][['Precaution_1', 'Precaution_2', 'Precaution_3', 'Precaution_4']]
        my_precautions = []
        if not pre.empty:
            for col in pre.columns:
                value = pre[col].iloc[0]
                if pd.notna(value) and value != '':
                    my_precautions.append(value)

        # Get medications
        med = medications[medications['Disease'] == dis]['Medication']
        my_medications = []
        if not med.empty:
            med_value = med.iloc[0]
            if pd.notna(med_value) and med_value != '':
                # Handle the string representation of list
                if isinstance(med_value, str) and med_value.startswith('[') and med_value.endswith(']'):
                    # Remove brackets and split by comma
                    med_value = med_value.strip('[]').replace("'", "").replace('"', '')
                    my_medications = [item.strip() for item in med_value.split(',')]
                else:
                    my_medications = [med_value]

        # Get diet
        die = diets[diets['Disease'] == dis]['Diet']
        my_diet = []
        if not die.empty:
            die_value = die.iloc[0]
            if pd.notna(die_value) and die_value != '':
                # Handle the string representation of list
                if isinstance(die_value, str) and die_value.startswith('[') and die_value.endswith(']'):
                    # Remove brackets and split by comma
                    die_value = die_value.strip('[]').replace("'", "").replace('"', '')
                    my_diet = [item.strip() for item in die_value.split(',')]
                else:
                    my_diet = [die_value]

        # Get workout
        wrkout = workout[workout['disease'] == dis]['workout']
        my_workout = []
        if not wrkout.empty:
            for item in wrkout:
                if pd.notna(item) and item != '':
                    my_workout.append(item)

        return desc, my_precautions, my_medications, my_diet, my_workout
    except Exception as e:
        print(f"Error in helper function: {e}")
        return "Description not available", [], [], [], []

symptoms_dict = {'itching': 0, 'skin_rash': 1, 'nodal_skin_eruptions': 2, 'continuous_sneezing': 3, 'shivering': 4, 'chills': 5, 'joint_pain': 6, 'stomach_pain': 7, 'acidity': 8, 'ulcers_on_tongue': 9, 'muscle_wasting': 10, 'vomiting': 11, 'burning_micturition': 12, 'spotting_ urination': 13, 'fatigue': 14, 'weight_gain': 15, 'anxiety': 16, 'cold_hands_and_feets': 17, 'mood_swings': 18, 'weight_loss': 19, 'restlessness': 20, 'lethargy': 21, 'patches_in_throat': 22, 'irregular_sugar_level': 23, 'cough': 24, 'high_fever': 25, 'sunken_eyes': 26, 'breathlessness': 27, 'sweating': 28, 'dehydration': 29, 'indigestion': 30, 'headache': 31, 'yellowish_skin': 32, 'dark_urine': 33, 'nausea': 34, 'loss_of_appetite': 35, 'pain_behind_the_eyes': 36, 'back_pain': 37, 'constipation': 38, 'abdominal_pain': 39, 'diarrhoea': 40, 'mild_fever': 41, 'yellow_urine': 42, 'yellowing_of_eyes': 43, 'acute_liver_failure': 44, 'fluid_overload': 45, 'swelling_of_stomach': 46, 'swelled_lymph_nodes': 47, 'malaise': 48, 'blurred_and_distorted_vision': 49, 'phlegm': 50, 'throat_irritation': 51, 'redness_of_eyes': 52, 'sinus_pressure': 53, 'runny_nose': 54, 'congestion': 55, 'chest_pain': 56, 'weakness_in_limbs': 57, 'fast_heart_rate': 58, 'pain_during_bowel_movements': 59, 'pain_in_anal_region': 60, 'bloody_stool': 61, 'irritation_in_anus': 62, 'neck_pain': 63, 'dizziness': 64, 'cramps': 65, 'bruising': 66, 'obesity': 67, 'swollen_legs': 68, 'swollen_blood_vessels': 69, 'puffy_face_and_eyes': 70, 'enlarged_thyroid': 71, 'brittle_nails': 72, 'swollen_extremeties': 73, 'excessive_hunger': 74, 'extra_marital_contacts': 75, 'drying_and_tingling_lips': 76, 'slurred_speech': 77, 'knee_pain': 78, 'hip_joint_pain': 79, 'muscle_weakness': 80, 'stiff_neck': 81, 'swelling_joints': 82, 'movement_stiffness': 83, 'spinning_movements': 84, 'loss_of_balance': 85, 'unsteadiness': 86, 'weakness_of_one_body_side': 87, 'loss_of_smell': 88, 'bladder_discomfort': 89, 'foul_smell_of urine': 90, 'continuous_feel_of_urine': 91, 'passage_of_gases': 92, 'internal_itching': 93, 'toxic_look_(typhos)': 94, 'depression': 95, 'irritability': 96, 'muscle_pain': 97, 'altered_sensorium': 98, 'red_spots_over_body': 99, 'belly_pain': 100, 'abnormal_menstruation': 101, 'dischromic _patches': 102, 'watering_from_eyes': 103, 'increased_appetite': 104, 'polyuria': 105, 'family_history': 106, 'mucoid_sputum': 107, 'rusty_sputum': 108, 'lack_of_concentration': 109, 'visual_disturbances': 110, 'receiving_blood_transfusion': 111, 'receiving_unsterile_injections': 112, 'coma': 113, 'stomach_bleeding': 114, 'distention_of_abdomen': 115, 'history_of_alcohol_consumption': 116, 'fluid_overload.1': 117, 'blood_in_sputum': 118, 'prominent_veins_on_calf': 119, 'palpitations': 120, 'painful_walking': 121, 'pus_filled_pimples': 122, 'blackheads': 123, 'scurring': 124, 'skin_peeling': 125, 'silver_like_dusting': 126, 'small_dents_in_nails': 127, 'inflammatory_nails': 128, 'blister': 129, 'red_sore_around_nose': 130, 'yellow_crust_ooze': 131}
diseases_list = {15: 'Fungal infection', 4: 'Allergy', 16: 'GERD', 9: 'Chronic cholestasis', 14: 'Drug Reaction', 33: 'Peptic ulcer diseae', 1: 'AIDS', 12: 'Diabetes ', 17: 'Gastroenteritis', 6: 'Bronchial Asthma', 23: 'Hypertension ', 30: 'Migraine', 7: 'Cervical spondylosis', 32: 'Paralysis (brain hemorrhage)', 28: 'Jaundice', 29: 'Malaria', 8: 'Chicken pox', 11: 'Dengue', 37: 'Typhoid', 40: 'hepatitis A', 19: 'Hepatitis B', 20: 'Hepatitis C', 21: 'Hepatitis D', 22: 'Hepatitis E', 3: 'Alcoholic hepatitis', 36: 'Tuberculosis', 10: 'Common Cold', 34: 'Pneumonia', 13: 'Dimorphic hemmorhoids(piles)', 18: 'Heart attack', 39: 'Varicose veins', 26: 'Hypothyroidism', 24: 'Hyperthyroidism', 25: 'Hypoglycemia', 31: 'Osteoarthristis', 5: 'Arthritis', 0: '(vertigo) Paroymsal  Positional Vertigo', 2: 'Acne', 38: 'Urinary tract infection', 35: 'Psoriasis', 27: 'Impetigo'}

# Model Prediction function
def get_predicted_value(patient_symptoms):
    input_vector = np.zeros(len(symptoms_dict))
    valid_symptoms = []
    invalid_symptoms = []
    
    for item in patient_symptoms:
        # Try exact match first
        if item in symptoms_dict:
            input_vector[symptoms_dict[item]] = 1
            valid_symptoms.append(item)
        else:
            # Try fuzzy matching - remove common suffixes and check
            base_item = item.lower().replace('ing', '').replace('ed', '').replace('s', '').strip()
            found = False
            
            for symptom_key in symptoms_dict.keys():
                symptom_base = symptom_key.lower().replace('ing', '').replace('ed', '').replace('s', '').strip()
                if base_item == symptom_base:
                    input_vector[symptoms_dict[symptom_key]] = 1
                    valid_symptoms.append(symptom_key)
                    found = True
                    break
            
            if not found:
                invalid_symptoms.append(item)
    
    if len(valid_symptoms) == 0:
        raise ValueError(f"No valid symptoms found. Invalid symptoms: {invalid_symptoms}")
    
    if len(invalid_symptoms) > 0:
        print(f"Warning: Could not match these symptoms: {invalid_symptoms}")
    
    return diseases_list[svc.predict([input_vector])[0]]




# creating routes========================================


@app.route("/")
def index():
    return render_template("index.html")

# Define a route for the home page
@app.route('/predict', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        symptoms = request.form.get('symptoms')
        print(symptoms)
        if symptoms == "Symptoms":
            message = "Please either write symptoms or you have written misspelled symptoms"
            return render_template('index.html', message=message)
        else:
            user_symptoms = [s.strip() for s in symptoms.split(',')]
            user_symptoms = [symptom.strip("[]' ") for symptom in user_symptoms]
            try:
                predicted_disease = get_predicted_value(user_symptoms)
                dis_des, my_precautions, medications, my_diet, workout = helper(predicted_disease)
                
                # Save prediction for logged-in users
                if 'user_id' in session:
                    db = get_db()
                    cursor = db.cursor()
                    cursor.execute(
                        'INSERT INTO predictions (user_id, symptoms, predicted_disease) VALUES (?, ?, ?)',
                        (session['user_id'], ','.join(user_symptoms), predicted_disease)
                    )
                    db.commit()
                
                # Redirect to result page with all outputs
                return render_template('result.html', predicted_disease=predicted_disease, dis_des=dis_des,
                                      my_precautions=my_precautions, medications=medications, my_diet=my_diet,
                                      workout=workout)
            except ValueError as e:
                message = str(e)
                return render_template('index.html', message=message)
            except Exception as e:
                message = f"An error occurred: {str(e)}"
                return render_template('index.html', message=message)
    return render_template('index.html')



# about view funtion and path
@app.route('/about')
def about():
    return render_template("about.html")
# contact view funtion and path
@app.route('/contact')
def contact():
    return render_template("contact.html")

# developer view funtion and path
@app.route('/developer')
def developer():
    return render_template("developer.html")

# about view funtion and path
@app.route('/blog')
def blog():
    return render_template("blog.html")

# --- Database Setup ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )''')
        # Check if 'is_admin' column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'is_admin' not in columns:
            cursor.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')
        
        # Create predictions table
        cursor.execute('''CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            symptoms TEXT,
            predicted_disease TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- User Context for Templates ---
@app.context_processor
def inject_user():
    return dict(logged_in=('user_id' in session), user_name=session.get('user_name'), is_admin=is_admin())

def get_current_user_email():
    user_id = session.get('user_id')
    if not user_id:
        return None
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT email FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    return row[0] if row else None

def is_admin():
    return session.get('user_id') and get_current_user_email() == ADMIN_EMAIL

# --- Register Route ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_password))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered. Please log in.', 'danger')
            return render_template('register.html')
    return render_template('register.html')

# --- Login Route ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, name, password FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'danger')
            return render_template('login.html')
    return render_template('login.html')

# --- Logout Route ---
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Admin Panel ---
@app.route('/admin', methods=['GET'])
def admin_panel():
    if not session.get('user_id') or not is_admin():
        flash('You must be the admin to access the admin panel.', 'danger')
        return redirect(url_for('index'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, name, email FROM users')
    users = cursor.fetchall()
    return render_template('admin.html', users=users)

@app.route('/admin/add', methods=['POST'])
def admin_add_user():
    if not session.get('user_id') or not is_admin():
        flash('You must be the admin to perform this action.', 'danger')
        return redirect(url_for('index'))
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    hashed_password = generate_password_hash(password)
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_password))
        db.commit()
        flash('User added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Email already exists.', 'danger')
    return redirect(url_for('admin_panel'))

@app.route('/admin/edit/<int:user_id>', methods=['POST'])
def admin_edit_user(user_id):
    if not session.get('user_id') or not is_admin():
        flash('You must be the admin to perform this action.', 'danger')
        return redirect(url_for('index'))
    name = request.form['name']
    email = request.form['email']
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute('UPDATE users SET name = ?, email = ? WHERE id = ?', (name, email, user_id))
        db.commit()
        flash('User updated successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Email already exists.', 'danger')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('user_id') or not is_admin():
        flash('You must be the admin to perform this action.', 'danger')
        return redirect(url_for('index'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_panel'))

# --- Last Prediction Route ---
@app.route('/last_prediction')
def last_prediction():
    if 'user_id' not in session:
        flash('Please log in to view your last prediction.', 'warning')
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        'SELECT symptoms, predicted_disease, created_at FROM predictions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
        (session['user_id'],)
    )
    row = cursor.fetchone()
    
    if row:
        symptoms, predicted_disease, created_at = row
        # Get full details for the predicted disease
        dis_des, my_precautions, medications, my_diet, workout = helper(predicted_disease)
        return render_template('last_prediction.html', 
                              symptoms=symptoms, 
                              predicted_disease=predicted_disease, 
                              created_at=created_at,
                              dis_des=dis_des,
                              my_precautions=my_precautions,
                              medications=medications,
                              my_diet=my_diet,
                              workout=workout)
    else:
        flash('No predictions found. Make your first prediction!', 'info')
        return redirect(url_for('index'))

# --- Debug: List all routes ---
@app.route('/routes')
def list_routes():
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote(f"{rule.endpoint:30s} {methods:20s} {str(rule)}")
        output.append(line)
    return '<pre>' + '\n'.join(output) + '</pre>'

# --- Initialize DB on every run ---
init_db()

if __name__ == '__main__':
    app.run(debug=True)