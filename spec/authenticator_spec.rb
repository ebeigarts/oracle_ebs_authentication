require "spec_helper"

describe "Authenticator" do
  before(:all) do
    if DATABASE_NAME && DATABASE_USERNAME && DATABASE_PASSWORD
      plsql.connect! DATABASE_USERNAME, DATABASE_PASSWORD, DATABASE_NAME
    else
      pending "You need to specify DATABASE_NAME, DATABASE_USERNAME, DATABASE_PASSWORD"
    end
  end

  before(:each) do
    @auth = OracleEbsAuthentication::Authenticator.new
    @user = "SIMANRAI"
    @password = "welcome1"
  end

  describe "#get_fnd_password" do
    it "should get APPS password and validate user password" do
      @auth.get_fnd_password(@user, @password).should_not be_nil
    end

    it "should not get APPS password for non-existing user" do
      @auth.get_fnd_password("XXX", @password).should be_nil
    end

    it "should not get APPS password for wrong user password" do
      @auth.get_fnd_password(@user, "XXX").should be_nil
    end
  end

  describe "#validate_user_password" do
    it "should validate user password for given user" do
      @auth.validate_user_password(@user, @password).should be_true
    end
  end

  describe "#get_fnd_responsibilities" do
    it "should return responsibility names for given user" do
      @auth.get_fnd_responsibilities("HINKKJUH").should include("System Administrator")
    end
  end
end
