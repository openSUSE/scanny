# 2011/09/12 slms/admin/app/controllers/app_manual_packages_controller.rb
class AppManualPackagesController < ApplicationController
  filter_resource_access
  filter_access_to :push_changes_to_studio, :require => :manage
  filter_access_to :create_update_box, :require => :manage
  filter_access_to :package_set, :require => :manage
  before_filter :get_appliance

  def index
    @app_manual_packages = @appliance.app_manual_packages(:joins => :package, :order => "user_sel_status DESC, name ASC")
  end

  def package_set
    ok = true
    params.each do |key,value|
      next unless ['true', 'false', ''].include? value
      value = eval(value)  # TESTCASE: CWE-95
      app_manual_package = AppManualPackage.find(key.to_i)
      next unless app_manual_package #unknown package
      next if app_manual_package.user_sel_status == value #nothing change
      ok &&= app_manual_package.update_attributes :user_sel_status => value, :already_used => false
    end

    if ok
      flash[:notice] = _('Package status is changed')
    else
      flash[:error] = _('Failed to change package status for some appliances')
    end

    respond_to do |format|
      format.html { redirect_to appliance_app_manual_packages_url }
    end
  end

end
