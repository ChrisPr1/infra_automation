#!/usr/bin/env ruby -x
require 'trollop'
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
    opt :folder, "Folder+Path in vCenter to deploy this template to", :short => 'f', :type => :string, :default => "POC"
    opt :datacenter, "Datacenter in vCenter", :short => 'd', :type => :string, :default => "Matrix"
    #rbvmomi_datacenter_opt

    text <<-EOS
 OS Customization options:
    EOS
    opt :domainname, "Specify domainname for Guest OS", :short => :none, :type => :string, :default => "foo.com"
    opt :netmask, "Specify Netmask for Guest OS", :short => :none, :type => :string, :default => "255.255.255.0"
    opt :gateway, "Specify Default Gateway address for Guest OS", :short => :none, :type => :string, :default => "192.168.1.1"
    opt :dnsservers, "Specify space delimited list of DNS Servers for Guest OS", :short => :none, :type => :string, :default => "192.168.1.2 192.168.1.3"
    opt :dnssearch, "Specify space delimited list of DNS Search Domains for Guest OS", :short => :none, :type => :string, :default => "foo.com"
    opt :numCPUs, "Number of CPU's allocated to VM", :short => :none, :type => :int, :default => 4
    opt :memoryMB, "Amount of memory in MB allocated to VM", :short => :none, :type => :int, :default => 8192
    opt :notes, "Notes to add to VM Container", :short => 'n', :type => :string
    opt :template, "Name of source template to clone, including full path", :short => 't', :type => :string
    opt :target_vm, "Name of VM to create", :short => 'v', :type => :string
  end #return opts = Trollop.options do

  Trollop.die("must specify Vcenter host to connect to") unless opts[:host]
  Trollop.die("must specify User to connect to vcenter as") unless opts[:user]
  Trollop.die("must specify VM Template to clone") unless opts[:template]
  Trollop.die("must specify Name of VM to clone to") unless opts[:target_vm]
  Trollop.die("must specify Datacenter within Vcenter") unless opts[:datacenter]

  if opts[:password] == ""
    print "Password: "
    opts[:password] = STDIN.noecho(&:gets).chomp
    print "\n"
  end

  return opts

end #getops method




def create_dnsrecord (user, password, hostname, domainname)
  #this method was for a specific clients environment where they used 'Men & Mice' ipam for 
  #Active Directory DNS integration and replication.
  
  #This method could be replaced with a method to update named via dyndns and keys or other
  #DNS name record creation


  # menandmice settings
  #hardcoded for now. could pass these as command line args in teh future. not
  #sure if there is any benefit to passing in versus hardcoding.
  mmserver = 'menmice01.foo.com'
  zone_name = domainname+"."
  ping_verify = true
  claim_time= 30
  #hardcoding range here to avoid conflicts with HP Matrix orchestrator which
  # has its own ipam and is allocating IPs from 10.15.184.0/22 from 184.1
  #upwards
  ip_range = '192.168.1.0/24'
  exclude_dhcp = true

  # create a client connection to the Men&Mice server denoted by
  #mmserver in the settings section immediately above and teh user/pass
  #passed into this method
  client = MmJsonClient::Client.new(server: mmserver,
                                  username: user,
                                  password: password)
  client.login

  #first, get a reference to the dns zone specified in the settings section by domain
  response = client.get_dns_zones(filter: "name:^#{zone_name}$")
  if response.total_results == 0
    abort "ERROR:     DNS Zone for #{zone_name} not found"
  end
  dns_zone = response.dns_zones.first

  #check to see if dns record already exists, and if so, abort
  record_filter = "name:^#{hostname}$"
  response = client.get_dns_records(filter: record_filter,
                                  dns_zone_ref: dns_zone.ref)
  if response.total_results >= 1
    abort "ERROR:     DNS record for #{hostname}.#{zone_name} already exists"
  end

  #get a reference to the IP range specified above in settings
  response = client.get_ranges(filter: "name:^#{ip_range}$")
  if response.total_results == 0
    abort "ERROR:     IP Range #{ip_range} not found"
  end
  range = response.ranges.first

  # get the next free IP available in the range
  response = client.get_next_free_address(range_ref: range.ref,
                                          ping: ping_verify,
                                          exclude_dhcp: exclude_dhcp,
                                          temporary_claim_time: claim_time)
  if ! response.address
    abort "ERROR:     Unable to allocate IP address from Men&Mice IPAM"
  else
    ip_address = response.address
  end


  #now add the dns record, and abort if more than
  dns_record = MmJsonClient::DNSRecord.new(name: hostname, type: 'A', ttl: nil,
                                         data: ip_address, enabled: true,
                                         dns_zone_ref: dns_zone.ref)
  response = client.add_dns_record(dns_record: dns_record)
  if  ! response.ref
    abort "ERROR:     There was a problem creating DNS record for #{hostname}.#{zone_name} "
  end

  #do a final check to ensure the DNS record was created and is queryable
  record_filter = "name:^#{hostname}$"
  response = client.get_dns_records(filter: record_filter,
                                  dns_zone_ref: dns_zone.ref)
  if response.total_results == 1
    puts "DNS record for #{hostname}.#{zone_name} with IP #{ip_address} successfully registered"
  else
    abort "ERROR:     Unable to register DNS record for #{hostname}.#{zone_name} "
  end

  client.logout

  return ip_address

end #create_dnsrecord

def delete_dnsrecord (user, password, hostname, domainname)

  #This function will be called IF there is a failure in the vm cloning process
  #as a cleanup of the DNS record created.

  # menandmice settings
  #hardcoded for now. could pass these as command line args in teh future. not
  #sure if there is any benefit to passing in versus hardcoding.
  mmserver = 'menmice01.foo.com'
  zone_name = domainname+"."
  ping_verify = true
  claim_time= 30

  client = MmJsonClient::Client.new(server: mmserver,
                                  username: user,
                                  password: password)
  client.login

  response = client.get_dns_zones(filter: "name:^#{zone_name}$")
  if response.total_results == 0
    abort "ERROR:     DNS Zone #{zone_name} not found"
  end
  dns_zone = response.dns_zones.first

  record_filter = "name:^#{hostname}$"

  response = client.get_dns_records(filter: record_filter,
                                      dns_zone_ref: dns_zone.ref)
  if response.total_results == 0
    abort "ERROR:     DNS record #{hostname}.#{zone_name} not found"
  end

  dns_record = response.dns_records.first

  client.remove_object(ref: dns_record.ref, obj_type: 'DNSRecord')

  record_filter = "name:^#{hostname}$"
    response = client.get_dns_records(filter: record_filter,
                                    dns_zone_ref: dns_zone.ref)
    if response.total_results == 0
      puts "DNS record for #{hostname}.#{zone_name} successfully unregistered"
    end

  client.logout


end #delete_dnsrecord




def create_customize_spec(source_vm_template, hostname, domainname, dnsservers_array, dnssearch_array, ipaddress, netmask, gateway_array)

  if /^rhel.*$/ =~ source_vm_template.summary.config.guestId
    identity = RbVmomi::VIM.CustomizationLinuxPrep({
      hostName: RbVmomi::VIM.CustomizationFixedName(name: hostname),
      domain:   domainname
    })
  elsif /^win.*$/ =~ source_vm_template.summary.config.guestId

    #windows template customization REQUIRES a valid license key, even if the template already has one
    if /^.*2012.*$/ =~ source_vm_template.summary.config.guestFullName
      windows_productId = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
    elsif /^.*2008\sR2.*$/ =~ source_vm_template.summary.config.guestFullName
      windows_productId = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
    end

    identity = RbVmomi::VIM.CustomizationSysprep({
      userData: RbVmomi::VIM.CustomizationUserData({
        computerName: VIM.CustomizationFixedName(name: hostname),
        fullName: "XYZ Company Inc",
        orgName: "XYZ COmpany Inc",
        #Windows Sysprep required a valid license key even If the template being cloned has a valid key installed (Volic or otherwise).
        productId: windows_productId
      }),
      guiUnattended: RbVmomi::VIM.CustomizationGuiUnattended({
        autoLogon: false,
        autoLogonCount: 1,
        password: nil,
        timeZone: "010"
      }),
      identification: RbVmomi::VIM.CustomizationIdentification({
        domainAdmin: nil,
        domainAdminPassword: nil,
        joinDomain: nil
      }),
      guiRunOnce: nil
    })

  end

  global_ip_settings = RbVmomi::VIM.CustomizationGlobalIPSettings({
    dnsServerList: dnsservers_array,
    dnsSuffixList: dnssearch_array
  })

  ip_addressref   = RbVmomi::VIM.CustomizationFixedIp(ipAddress: ipaddress)
  ip_settingsref  = RbVmomi::VIM.CustomizationIPSettings(ip: ip_addressref, subnetMask: netmask, gateway: gateway_array)
  adapter_mapping = RbVmomi::VIM.CustomizationAdapterMapping(adapter: ip_settingsref)

  customize_spec  = RbVmomi::VIM.CustomizationSpec({
    identity:         identity,
    nicSettingMap:    [adapter_mapping],
    globalIPSettings: global_ip_settings
  })

  return customize_spec

end #create_customize_spec




def create_config_spec (numCPUs, memoryMB, vm_source_pathname, vcenter_user, notes)

  date = Time.now
  config_spec = RbVmomi::VIM.VirtualMachineConfigSpec({
    numCPUs:          numCPUs,
    memoryMB:         memoryMB,
    annotation:    "Created with Template : #{vm_source_pathname}\n\nCreation Date: #{date}\n\nCreated by: #{vcenter_user}\n\n Notes at Creation Time: \n #{notes}"
  })

end #end create_config_spec



def clone_vm ( hostname, datacenter, source_vm_template, cluster, folder, customize_spec, config_spec, user, password, domainname)

  # create the relocateSpec object which defines the DC ComputeCluster to
  #create the VM under
  relocateSpec = VIM.VirtualMachineRelocateSpec(:pool => cluster.resourcePool )

  # customize_spec and config_spec are passed objects created in their own
  #method calls elsewhere in this program
  # important to NOT set poweron here as we modify the network info below and
  #then issue a seperate poweron command to VIM
  my_vm_spec = VIM.VirtualMachineCloneSpec(:location => relocateSpec,
                                          :customization => customize_spec,
                                          :config => config_spec,
                                          :powerOn => false,
                                          :template => false
                                          )

  newvm = source_vm_template.CloneVM_Task(:folder => folder, :name => hostname, :spec => my_vm_spec).wait_for_completion

  if newvm.class == RbVmomi::VIM::VirtualMachine
    puts "Successfully Created VM #{hostname} from template #{source_vm_template.name}"
  else
    #cleanup the now stale dns record
    delete_dnsrecord( user, password, hostname, domainname )
    abort "ERROR:     UNABLE TO CREATE VM #{hostname} from template #{source_vm_template.name}"
  end

  # Currently (Oct/16), the RHEL64 V3 template in use in the matrix leaves
  #the single network card in a 'disconnected' state at template deploy
  #time. The following query to the VirtualEthernetCard object of the VM
  #gets us the current config so we can modify it and send teh modify
  #request back to
  dnic = newvm.config.hardware.device.grep(RbVmomi::VIM::VirtualEthernetCard).find{|nic| nic.props}

  if dnic[:connectable][:startConnected].eql?false
    dnic[:connectable][:startConnected] = true
    mybackinginfo = VIM.VirtualEthernetCardNetworkBackingInfo(
       deviceName: 'Production Network'
    )
    dnic[:backing] = mybackinginfo

    spec = RbVmomi::VIM.VirtualMachineConfigSpec({
        :deviceChange => [{
        :operation => :edit,
        :device => dnic
        }],
    })
    newvm.ReconfigVM_Task(:spec => spec).wait_for_completion
    puts "Reconfigured VM #{hostname} to use Production Network and connect NIC1"
  end #if dnic[:connectable]...

  newvm.PowerOnVM_Task.wait_for_completion
  puts "Powering on VM #{hostname}"


end #clone_vm method

#Begin main program

#call the getopts method defined above and assign the returned hash to 'opts'
opts = getopts()

dnsservers_array = opts[:dnsservers].split(" ")
dnssearch_array = opts[:dnssearch].split(" ")
gateway_array= opts[:gateway].split(" ")
netmask=opts[:netmask]
vm_source_pathname = opts[:template]
hostname = opts[:target_vm]
domainname = opts[:domainname]
notes = opts[:notes]

#Create a VIM object reference to facilitate access to vcenter
VIM = RbVmomi::VIM

#now create the connection to vCenter and attempt to find the source template
#If the source template to use cannot be found then exit/abort with an error
#pass in our entire 'opts' hash to VIM.connect which includes the Trollop
#rubygem gathered user, password and host key/value pairs needed for VIM.connect
vim = VIM.connect opts
if vim.class != RbVmomi::VIM
  abort "ERROR:     Unable to connect to vcenter"
end

#get the username of the user logged into vcenter for adding to the 'Notes'
#section/VM Object Annotation information
vcenter_user = vim.serviceContent.sessionManager.currentSession.userName

datacenter = vim.serviceInstance.find_datacenter(opts[:datacenter]) or abort "datacenter not found"
if datacenter.class != RbVmomi::VIM::Datacenter
  abort "ERROR:     Unable to find #{opts[:datacenter]} in VCenter #{opts[:host]}"
end

source_vm_template = datacenter.find_vm(vm_source_pathname) or abort "VM not found"
if source_vm_template.class != RbVmomi::VIM::VirtualMachine
  abort "ERROR:     Unable to find #{vm_source_pathname} in Datacenter #{opts[:datacenter]}"
end

folder = datacenter.vmFolder.findByInventoryPath("Matrix/vm/#{opts[:folder]}")
if folder.class != RbVmomi::VIM::Folder
  abort "ERROR:     Unable to find #{opts[:folder]} in Datacenter #{opts[:datacenter]}"
end

cluster = datacenter.hostFolder.findByInventoryPath("Matrix/host/#{opts[:cluster]}")
if cluster.class != RbVmomi::VIM::ClusterComputeResource
  abort "ERROR:     Unable to find #{opts[:cluster]} in Datacenter #{opts[:datacenter]}"
end
# Now that the source VM has been identified and an object handler for it
#retrieved we need to get a free IP from Men&Mice IPAM and create a
#corresponding DNS recprd for the hostname with that IP
ip_address = create_dnsrecord(opts[:user], opts[:password], hostname, opts[:domainname])

#now create the customize_spec which contains the OS customization params
customize_spec = create_customize_spec(source_vm_template, hostname, domainname, dnsservers_array, dnssearch_array, ip_address, netmask, gateway_array)

# config spec is modifications to the VM container hardware. We just modify cpu
#and memory for now. Nic adds/removes, disk changes, etc can happen here or
# after cloning process. We also pass in vcenter_user for adding to the VM Object
#Annotation property ('Notes' section on the VM in vcenter UI)
config_spec = create_config_spec(opts[:numCPUs], opts[:memoryMB], vm_source_pathname, vcenter_user, notes)

#now clone the VM.
clone_vm(hostname, datacenter, source_vm_template, cluster, folder, customize_spec, config_spec, opts[:user], opts[:password], opts[:domainname])
