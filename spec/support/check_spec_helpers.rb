module CheckSpecHelpers
  def issue(*args)
    Scanny::Issue.new("scanned_file.rb", 1, *args)
  end
end