import os
import sys
sys.path.insert(0, '../Util')
import my_pypdftk as pypdftk

# Expands synonyms of form field names 
dob = ["dob", "date of birth", "birthday", "birthdate", "d.o.b.", "d.o.b"]
first_name = ["first name", "given name", "name"]
last_name = ["surname", "last name"]
ssn = ["social security", "social security number", "ssn", "social security no"]
gender = ["gender", "sex"]
postal_code = ["postal code", "zip", "zip code"]
work_phone = ["work phone", "work telephone", "cell", "work no"]
home_phone = ["home phone", "home telephone", "home no"]

categories = [dob, first_name, last_name, ssn, gender, postal_code, work_phone, home_phone]

def fill(data, in_file, out_file):
	'''
	Uses all permutations of the data to attempt to fill in the 
	form @in_file. Outputs to @out_file the filled pdf. 
	Requries that the pdf have interactive form fields with 
	sensible field names (not just 1,2,3). 
	'''
	expanded_data = permutateFields(data)
	#print(expanded_data)
	modified_data = pypdftk.modify_xfdf(in_file, expanded_data)
	print("Filled form with data: ")
	print(modified_data)
	generated_pdf = pypdftk.fill_form(in_file, modified_data, out_file=out_file)

def permutateFields(data):
	'''
	Generates more data key-value pairs using the synonyms.
	For any key that is in the category, all other synonyms 
	of the categories are added as keys to the same value. 
	For the gender category, the value of yes is also added 
	to the key of male/female (for possible buttons)
	'''
	expanded_data = data.copy()
	for key, value in data.items():
		for category in categories:
			if key.lower() in category:
				if category is gender:
					expanded_data[value] = "yes"
				for name in category:
					expanded_data[name] = value
	return expanded_data
