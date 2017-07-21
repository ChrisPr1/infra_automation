#!/usr/bin/env ruby
require 'trollop'
require 'rbvmomi'
require 'io/console'


def getopts()

  #Trollop module for rbvmomi has default :user :password :host vcenter required
  #options which we add to in the Customization options
  opts = Trollop.options do

    banner <<-EOS
Clone a VM.
 Usage:
  create_vm.rb [options] 
 VIM connection options:
    EOS
    opt :host, "vCenter Host", :type => :string, :short => 'o', :default => "vcenter01.foo.com"
    opt :port, "vCenter Port", :type => :int, :short => 'P', :default => 443
    #opt :"no-ssl", "don't use ssl", :type => :bool, :short => :none, :default => '0'
    opt :insecure, "don't verify ssl certificate", :short => 'k', :default => '1'
    opt :user, "vCenter Username", :short => 'u', :required => true, :default => ''
    opt :password, "vCenter Password", :short => 'p', :default => ''
    opt :path, "SOAP endpoint path", :short => :none, :default => '/sdk'
    opt :debug, "Log SOAP messages", :short => 'D', :default => false

    text <<-EOS
 VM location options:
    EOS
    opt :datacenter, "Datacenter in vCenter", :short => 'd', :type => :string, :default => "Datacenter01"
    opt :cluster, "vCenter Compute Cluster to deploy VM into", :short => 'c', :type => :string, :default => "Cluster01"
    opt :folder, "Folder+Path in vCenter to deploy this template to", :short => 'f', :type => :string, :default => ""
    opt :datastore, "Datastore to place VM in", :type => :string, :default => "Datastore01"
    #rbvmomi_datacenter_opt

    text <<-EOS
 OS Customization options:
    EOS
    opt :target_vm, "Name of VM to create", :short => 'v', :type => :string, :required => true
    opt :numCPUs, "Number of CPU's allocated to VM", :short => :none, :type => :int, :default => 4
    opt :memoryMB, "Amount of memory in MB allocated to VM", :short => :none, :type => :int, :default => 8192
    opt :disk0_Size, "Size in KBytes of disk 1", :type => :int, :default => 41943040
    opt :osType, "Vcenter OS ID string", :short => 'O', :type => :string, :default => "rhel6_64Guest"
    opt :networkId, "Network ID/VLAN Name to connect nic 1 to", :short => 'N', :type => :string, :default => "dvSwitch0_vlan001"
    opt :domainname, "Specify domainname for Guest OS", :short => :none, :type => :string, :default => "foo.com"
    opt :netmask, "Specify Netmask for Guest OS", :short => :none, :type => :string, :default => "255.255.255.0"
    opt :gateway, "Specify Default Gateway address for Guest OS", :short => :none, :type => :string, :default => "192.168.1.1"
    opt :dnsservers, "Specify space delimited list of DNS Servers for Guest OS", :short => :none, :type => :string, :default => "192.168.1.2 192.168.1.3"
    opt :dnssearch, "Specify space delimited list of DNS Search Domains for Guest OS", :short => :none, :type => :string, :default => "foo.com"
    opt :notes, "Notes to add to VM Container", :short => 'n', :type => :string
  end #return opts = Trollop.options do

  if opts[:password] == ""
    print "Password: "
    opts[:password] = STDIN.noecho(&:gets).chomp
    print "\n"
  end

  return opts

end #getops method


def create_vm_config ( hostname, vmware_clientId, cpus, memory, datastore, networkObj, disk0_Size )

network_backing = ""

if networkObj.class == VIM::Network
  network_backing = VIM.VirtualEthernetCardNetworkBackingInfo( deviceName: networkObj.name )
elsif networkObj.class == VIM::DistributedVirtualPortgroup
  switch, pg_key = networkObj.collect 'config.distributedVirtualSwitch', 'key'
  port = RbVmomi::VIM.DistributedVirtualSwitchPortConnection( switchUuid: switch.uuid, portgroupKey: pg_key)
  network_backing = VIM.VirtualEthernetCardDistributedVirtualPortBackingInfo( port: port )
end

vm_cfg = {
  name: hostname,
  guestId: vmware_clientId,
  files: { vmPathName: datastore },
  numCPUs: cpus,
  memoryMB: memory,
  deviceChange: [
    {
      operation: :add,
      device: VIM.ParaVirtualSCSIController( key: 1000, busNumber: 0, sharedBus: :noSharing,)
    }, {
      operation: :add,
      fileOperation: :create,
      device: VIM.VirtualDisk(
        key: 0,
        backing: VIM.VirtualDiskFlatVer2BackingInfo( fileName: datastore, diskMode: :persistent, thinProvisioned: true,),
        controllerKey: 1000,
        unitNumber: 0,
        capacityInKB: disk0_Size,
      )
    }, {
      operation: :add,
      device: VIM.VirtualVmxnet3(
        key: 0,
        deviceInfo: { label: 'Network Adapter 1', summary: 'Network Adapter 1', },
        backing: network_backing,
        addressType: 'generated'
      )
    }

  ]
}

return vm_cfg

end

#Begin main program

#call the getopts method defined above and assign the returned hash to 'opts'
opts = getopts()

dnsservers_array = opts[:dnsservers].split(" ")
dnssearch_array = opts[:dnssearch].split(" ")
gateway_array= opts[:gateway].split(" ")
netmask=opts[:netmask]
hostname = opts[:target_vm]
vmware_clientId = opts[:osType]
networkId = opts[:networkId]
datastore = "["+opts[:datastore]+"]"
cpus = opts[:numCPUs]
memory = opts[:memoryMB]
disk0_Size = opts[:disk0_Size]
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

folder = datacenter.vmFolder.findByInventoryPath("wbdc01/vm/#{opts[:folder]}")
if folder.class != RbVmomi::VIM::Folder
  abort "ERROR:     Unable to find #{opts[:folder]} in Datacenter #{opts[:datacenter]}"
end

cluster = datacenter.hostFolder.findByInventoryPath("wbdc01/host/#{opts[:cluster]}")
if cluster.class != RbVmomi::VIM::ClusterComputeResource
  abort "ERROR:     Unable to find #{opts[:cluster]} in Datacenter #{opts[:datacenter]}"
end

networkObj = datacenter.hostFolder.findByInventoryPath("wbdc01/network/#{opts[:networkId]}")

vm_config = create_vm_config( hostname, vmware_clientId, cpus, memory, datastore, networkObj, disk0_Size )

myresourcePool = cluster.resourcePool

myVM = folder.CreateVM_Task(:config => vm_config, :pool => myresourcePool).wait_for_completion

if myVM.class != RbVmomi::VIM::VirtualMachine
  abort "ERROR:   VM not created"
end

myMacaddress = ""

myVM.config.hardware.device.each do |device|
  if ((device.class == RbVmomi::VIM::VirtualVmxnet3) && ( device.deviceInfo.label == "Network adapter 1" ))
      myMacaddress = device.macAddress
  end
end

puts myMacaddress
