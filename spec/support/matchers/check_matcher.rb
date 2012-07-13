RSpec::Matchers.define :check do |input|
  chain :without_issues do
    @type = :no_issues
  end

  chain :with_n_issues do |count|
    @type = :issue_count
    @count = count
  end

  chain :with_issue do |issue|
    @type = :issue
    @issue = issue
  end

  chain :with_issues do |*issues|
    @type = :issues
    @issues = issues.flatten
  end

  match do |scanny|
    check_data = scanny.check("scanned_file.rb", input)

    case @type
      when :no_issues
        check_data[:issues].should be_empty

      when :issue_count
        check_data[:issues].size.should == @count

      when :issue
        check_data[:issues].size.should == 1
        check_data[:issues][0].should == @issue

      when :issues
        check_data[:issues].size.should == @issues.size
        check_data[:issues].should =~ @issues

      else
        raise "Unknown check type: #{type.inspect}."
    end
  end
end