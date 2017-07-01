#!/usr/bin/env ruby

require 'rbvmomi'
require 'rbvmomi/trollop'
require 'mm_json_client'
require 'io/console'

def getopts()

  #initialize password to nil so we can check it later to see if its been set
  #during Trollop.options call

  #Trollop module for rbvmomi has default :user :password :host vcenter required
  #options which we add to in the Customization options
  opts = Trollop.options do

    banner <<-EOS
Clone a VM.
 Usage:
  clone_vm.rb [options] source_vm dest_vm
  VIM connection options:
    EOS
      opt :host, "vCenter Host", :type => :string, :short => 'o', :default => "vcenter01.foo.com"
      opt :port, "vCenter Port", :type => :int, :short => 'P', :default => 443
      #opt :"no-ssl", "don't use ssl", :type => :bool, :short => :none, :default => '0'
      opt :insecure, "don't verify ssl certificate", :short => 'k', :default => '1'
      opt :user, "vCenter Username", :short => 'u', :default => ''
      opt :password, "vCenter Password", :short => 'p', :default => ''
      opt :path, "SOAP endpoint path", :short => :none, :default => '/sdk'
      opt :debug, "Log SOAP messages", :short => 'D', :default => false

    text <<-EOS
  VM location options:
    EOS
       opt :cluster, "vCenter Compute Cluster to deploy VM into", :short => 'c', :type => :string, :default => "HP CMS"
       opt :folder, "Folder (including path) where VM to be deleted is located", :short => 'f', :type => :string
       opt :datacenter, "Datacenter in vCenter", :short => 'd', :type => :string, :default => "Matrix"
       opt :target_vm, "Name of VM to create", :short => 'v', :type => :string
  end #return opts = Trollop.options do

  Trollop.die("must specify Vcenter host to connect to") unless opts[:host]
  Trollop.die("must specify User to connect to vcenter as") unless opts[:user]
  Trollop.die("must specify Folder (including path) in #{opts[:datacenter]} where VM to be deleted is located") unless opts[:folder]
  Trollop.die("must specify Name of VM to destroy") unless opts[:target_vm]

  if opts[:password] == ""
    print "Password: "
    opts[:password] = STDIN.noecho(&:gets).chomp
    print "\n"
  end

  return opts

end #getops method


opts = getopts()

path_to_vm = "#{opts[:folder]}/#{opts[:target_vm]}"

#Create a VIM object reference to facilitate access to vcenter
VIM = RbVmomi::VIM

#now create the connection to vCenter and attempt to find the VM we wish
#to destroy.
#vim = RbVmomi::VIM.connect host: vcenter_host, user: username, password: password, insecure: true
vim = VIM.connect opts
datacenter = vim.serviceInstance.content.rootFolder.traverse(opts[:datacenter], VIM::Datacenter) or abort "datacenter not found"
vm = datacenter.find_vm(path_to_vm) or abort "VM not found"
puts "Found VM #{vm.name} in Folder #{opts[:folder]}"

if /^poweredOn$/ =~ vm.runtime.powerState
  puts "Host is powered on : powering off VM #{opts[:target_vm]} before Destruction"
  vm.PowerOffVM_Task.wait_for_completion
else
  puts "Host is currently powered off, proceeding to VM destruction/removal"
end

begin
  puts "Destroying VM #{opts[:target_vm]}"
  vm.Destroy_Task.wait_for_completion
rescue RbVmomi::Fault
  exit
end

# Now remove the associated DNS entry

dns_zone_name = 'foo.com.'
mmserver = 'menmice01.foo.com'

client = MmJsonClient::Client.new(server: mmserver,
                                  username: opts[:user],
                                  password: opts[:password])

client.login or abort "Unable to login to Men&Mice Server"

response = client.get_dns_zones(filter: "name:^#{dns_zone_name}$")
if response.total_results == 0
  raise "DNS Zone #{dns_zone_name} not found"
  exit
end

dns_zone = response.dns_zones.first

record_filter = "name:^#{opts[:target_vm]}$ type:A"
response = client.get_dns_records(filter: record_filter,
                                  dns_zone_ref: dns_zone.ref)
if response.total_results == 0
  raise "DNS record #{opts[:target_vm]}.#{dns_zone_name} not found"
  exit
end
dns_record = response.dns_records.first

client.remove_object(ref: dns_record.ref, obj_type: 'DNSRecord')

puts "DNS record #{opts[:target_vm]}.#{dns_zone_name} removed"

client.logout
