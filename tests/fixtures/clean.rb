require 'securerandom'
require 'digest'

class SafeController < ApplicationController
  def show
    user = User.where(name: params[:name])
  end

  def create
    User.create(user_params)
  end

  def generate_token
    SecureRandom.hex(32)
  end

  def hash_password(pwd)
    Digest::SHA256.hexdigest(pwd)
  end

  private

  def user_params
    params.require(:user).permit(:name, :email)
  end
end
