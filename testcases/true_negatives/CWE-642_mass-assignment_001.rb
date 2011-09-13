# 2011/09/12: slms/admin/app/controllers/users_controller.rb
#
#  Copyright (c) 2009 Novell, Inc.
#  All Rights Reserved.
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License as
#  published by the Free Software Foundation; version 2.1 of the license.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this library; if not, contact Novell, Inc.
#
#  To contact Novell about this file by physical or electronic mail,
#  you may find current contact information at www.novell.com

class UsersController < ApplicationController
  filter_resource_access :additional_collection => [:generate_key]

  skip_before_filter :login_required, :only => [:forgot_password] # RORSCAN_ITL
  before_filter :find_user, :only => [:edit, :change_settings, :update, :update_settings, :destroy_form, :destroy]
  before_filter :assign_default_api_name, :only => [ :edit, :change_settings ]

  filter_parameter_logging :admin_password_confirmation # RORSCAN_ITL

  def generate_key
    respond_to do |format|
      format.html { render :partial => "api_key",
                    :locals => { :api_key => Slms::Utils.make_random_string(20,true).to_s } }
    end
  end

  def update
    # RORSCAN_INL_2: This is not authentication or authorization check, it's a confirmation that the current user knows their password
    if params['admin'].try(:[], :admin_password_confirmation) &&
      User.find_by_email(current_user[:email]).authenticated?(params['admin'][:admin_password_confirmation])

      clear_api_options unless params.has_key?("api_enabled")

      # Do not change a password if it is not set
      if params.has_key? :user and params[:user].has_key? :password and params[:user][:password] == ""
        Rails.logger.info "Password not set, not changing"
        params[:user].delete :password
      end
      # RORSCAN_INL: Secured by attr_accessible in User model
      if @user.update_attributes(params[:user]) # TESTCASE: CWE-642
        respond_to do |format|
          format.js { render :text => 'success' }
          format.html { redirect_to users_path }
        end
        return
      end
    else
      @user.errors.add_to_base "Confirm your password before modifying a user account"
    end

    respond_to do |format|
      format.js { render :action => 'edit', :layout => 'facebox' }
      format.html
    end
  end

end
