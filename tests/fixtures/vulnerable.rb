require 'digest'

class VulnerableController < ApplicationController
  # SQL injection via string interpolation
  def show
    user = User.where("name = '#{params[:name]}'")
  end

  # XSS via html_safe
  def render_content
    content = params[:body].html_safe
  end

  # Command injection via backtick with interpolation
  def run_cmd
    result = `ls #{params[:dir]}`
  end

  # Command injection via system
  def execute
    system("echo #{params[:msg]}")
  end

  # Hardcoded secret
  SECRET_TOKEN = "my_super_secret_token_12345"

  # Mass assignment via permit(:all)
  def create
    User.create(params.require(:user).permit(:all))
  end

  # Path traversal via File.read with params
  def download
    File.read(params[:path])
  end

  # Insecure random
  def generate_token
    rand(1000000)
  end

  # Weak crypto: MD5
  def hash_password(pwd)
    Digest::MD5.hexdigest(pwd)
  end

  # Open redirect
  def redirect
    redirect_to params[:url]
  end

  # Eval injection
  def dynamic_eval
    eval(params[:code])
  end
end
