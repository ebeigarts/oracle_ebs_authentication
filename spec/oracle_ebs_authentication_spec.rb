require File.dirname(__FILE__) + '/spec_helper'
require File.dirname(__FILE__) + '/../lib/oracle_ebs_authentication'

describe "Authentication" do
  
  before(:each) do
    @db_name = "VIS"
    @gw_user = "APPLSYSPUB"
    @gw_password = "PUB"
    @fnd_name = "APPS"
    # Should set db_server_id if security level in FND_NODES table is set to SECURE
    @db_server_id = nil
    @auth = OracleEbsAuthentication::Authenticator.new(@db_name, @gw_user, @gw_password, @fnd_name, @db_server_id)
    @user = "hrms"
    @password = "welcome"
    @apps_password = "APPS"
    @responsibilities = ["System Administrator"]
  end
  
  it "should set user name and password" do
    @auth.user = @user
    @auth.password = @password
    @auth.user.should == @user
    @auth.password.should == @password
  end
  
  it "should get APPS password" do
    @auth.get_fnd_password(@user, @password).should == @apps_password.upcase
  end

  it "should get APPS password and validate user password" do
    @auth.get_fnd_password(@user, @password).should_not be_nil
    @auth.validate_user_password.should be_true
  end

  it "should validate user password for given user" do
    @auth.validate_user_password(@user, @password).should be_true
  end

  it "should not get APPS password for wrong database name" do
    @auth = OracleEbsAuthentication::Authenticator.new("WRONG", @gw_user, @gw_password, @fnd_name, @db_server_id)
    @auth.get_fnd_password(@user, @password).should be_nil
  end

  it "should not get APPS password for non-existing user" do
    @auth.get_fnd_password("XXX", @password).should be_nil
  end

  it "should not get APPS password for wrong user password" do
    @auth.get_fnd_password(@user, "XXX").should be_nil
  end

  it "should return user reponsibility list" do
    @auth.validate_user_password(@user, @password).should be_true
    (@auth.user_responsibilities & @responsibilities).should == @responsibilities
  end

  it "should return user_id and email" do
    @auth.validate_user_password(@user, @password).should be_true
    @auth.user_id.should_not be_nil
    @auth.email.should_not be_nil
  end

end

