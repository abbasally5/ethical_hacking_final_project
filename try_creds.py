from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

def run_all_login_attempts (username, password):
	binary = FirefoxBinary('geckodriver')
	driver = webdriver.Firefox(firefox_binary=binary)
	driver.implicitly_wait(5)
	try_google(username, password, driver)
	try_facebook(username, password, driver)
	#try_twitter(username, password, driver)
	try_instagram(username, password, driver)
	driver.close()

def try_google(username, password, driver):
	driver.get("https://accounts.google.com/signin/v2/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&service=mail&sacu=1&rip=1&flowName=GlifWebSignIn&flowEntry=ServiceLogin")
	driver.implicitly_wait(5)
	login_field = driver.find_element_by_name("identifier")
	login_field.click()
	login_field.send_keys(username)
	next = driver.find_element_by_id("identifierNext")
	next.click()
	element = WebDriverWait(driver, 3).until(EC.visibility_of_element_located((By.NAME, "password")))
	pswd_field = driver.find_element_by_name("password")
	pswd_field.click()
	pswd_field.send_keys(password)
	next = driver.find_element_by_id("passwordNext")
	next.click()

	try:
		starred = WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.LINK_TEXT, "Starred")))
		print("Google login SUCCEEDED")
	except:
		print("Google login attempt failed")

def try_facebook(username, password, driver):
	driver.get("https://www.facebook.com/")
	driver.implicitly_wait(5)
	login_field = driver.find_element_by_name("email")
	login_field.click()
	login_field.send_keys(username)
	pswd_field = driver.find_element_by_name("pass")
	pswd_field.click()
	pswd_field.send_keys(password)
	next = driver.find_element_by_id("u_0_x")
	next.click()

	try:
		status = WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.LINK_TEXT, "Sign up for Facebook")))
		print("Facebook login attempt failed")
	except:
		print("Facebook login SUCCEEDED")

def try_instagram(username, password, driver):
	driver.get("https://www.instagram.com/")
	driver.implicitly_wait(5)
	login_button = driver.find_element_by_link_text("Log in")
	login_button.click()
	login_field = driver.find_element_by_name("username")
	login_field.click()
	login_field.send_keys(username)
	pswd_field = driver.find_element_by_name("password")
	pswd_field.click()
	pswd_field.send_keys(password)
	pswd_field.send_keys(Keys.RETURN)

	try:
		status = WebDriverWait(driver, 3).until(EC.invisibility_of_element_located((By.LINK_TEXT, "Sign up")))
		print("Instagram login SUCCEEDED")
	except:
		print("Instagram login attempt failed")

#def try_twitter(username, password, driver):
#	driver.implicitly_wait(5)
#	login_field = driver.find_element_by_name("session[username_or_email]")
	# login_field.click()
	# login_field.send_keys(username)
	# pswd_field = driver.find_element_by_name("session[password]")
	# pswd_field.click()
	# pswd_field.send_keys(password)
	# pswd_field.send_keys(Keys.RETURN)
	#
	# try:
	# 	status = WebDriverWait(driver, 3).until(EC.invisibility_of_element_located((By.LINK_TEXT, "Forgot password?")))
	# 	print("Twitter login SUCCEEDED")
	# except:
	# 	print("Twitter login attempt failed")

if __name__ == "__main__":

	run_all_login_attempts("ethicalhackingdemo@gmail.com", "TEst123!")
