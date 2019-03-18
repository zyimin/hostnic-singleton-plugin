package driver

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/docker/go-plugins-helpers/network"
	"github.com/vishvananda/netlink"
	"github.com/yunify/docker-plugin-hostnic/log"
)

const (
	networkType         = "hostnic"
	containerVethPrefix = "eth"
	configDir           = "/etc/docker/hostnic"
)

type NicTable map[string]*HostNic

type HostNic struct {
	Name         string // e.g., "en0", "lo0", "eth0.100"
	HardwareAddr string
	Address      string
}

type Endpoint struct {
	id      string
	srcName string
	//portMapping []types.PortBinding // Operation port bindings
	dbIndex    uint64
	dbExists   bool
	sandboxKey string
}

func New() (*HostNicDriver, error) {
	err := os.MkdirAll(configDir, os.FileMode(0755))
	if err != nil {
		return nil, err
	}
	d := &HostNicDriver{
		networks: Networks{},
		lock:     sync.RWMutex{},
	}
	return d, nil
}

type Networks map[string]*Network

type Network struct {
	ID       string
	hostnic  HostNic
	IPv4Data *network.IPAMData
	endpoint *Endpoint
}

//HostNicDriver implements github.com/docker/go-plugins-helpers/network.Driver
type HostNicDriver struct {
	networks Networks
	lock     sync.RWMutex
}

func (d *HostNicDriver) GetCapabilities() (*network.CapabilitiesResponse, error) {
	return &network.CapabilitiesResponse{Scope: network.LocalScope}, nil
}

func (d *HostNicDriver) CreateNetwork(r *network.CreateNetworkRequest) error {
	log.Debug("CreateNetwork Called: [ %+v ]", r)
	log.Debug("CreateNetwork IPv4Data len : [ %v ]", len(r.IPv4Data))
	d.lock.Lock()
	defer d.lock.Unlock()

	if _, exists := d.networks[r.NetworkID]; exists {
		return fmt.Errorf("Exist network [%s]", r.NetworkID)
	}

	if r.IPv4Data == nil || len(r.IPv4Data) == 0 {
		return fmt.Errorf("Network gateway config miss.")
	}

	ipv4Data := r.IPv4Data[0]
	nw := Network{
		IPv4Data: ipv4Data,
		ID:       r.NetworkID,
		endpoint: &Endpoint{},
		hostnic: HostNic{
			Name: "",
		},
	}

	for k, v := range r.Options {
		if k == "com.docker.network.generic" {
			if genericOpts, ok := v.(map[string]interface{}); ok {
				for key, val := range genericOpts {
					if key == "host_iface" {
						nw.hostnic.Name = val.(string)
					}
					if key == "ip" {
						nw.hostnic.Address = val.(string)
					}
				}
			}
		}
	}

	if nw.hostnic.Name == "" {
		return fmt.Errorf("Miss host nic name.")
	}

	// TODO: find out mac address
	link := d.findLinkByName(nw.hostnic.Name)
	nw.hostnic.HardwareAddr = link.Attrs().HardwareAddr.String()

	d.networks[r.NetworkID] = &nw
	log.Info("RegisterNetwork [%s] IPv4Data : [ %+v ]", nw.ID, nw.IPv4Data)

	//d.saveConfig()
	return nil
}

func (d *HostNicDriver) AllocateNetwork(r *network.AllocateNetworkRequest) (*network.AllocateNetworkResponse, error) {
	log.Debug("AllocateNetwork Called: [ %+v ]", r)
	return nil, nil
}

func (d *HostNicDriver) DeleteNetwork(r *network.DeleteNetworkRequest) error {
	log.Debug("DeleteNetwork Called: [ %+v ]", r)
	d.lock.Lock()
	defer d.lock.Unlock()
	delete(d.networks, r.NetworkID)
	//d.saveConfig()
	return nil
}
func (d *HostNicDriver) FreeNetwork(r *network.FreeNetworkRequest) error {
	log.Debug("FreeNetwork Called: [ %+v ]", r)
	return nil
}
func (d *HostNicDriver) CreateEndpoint(r *network.CreateEndpointRequest) (*network.CreateEndpointResponse, error) {
	d.lock.Lock()
	defer d.lock.Unlock()

	log.Debug("CreateEndpoint Called: [ %+v ]", r)
	log.Debug("r.Interface: [ %+v ]", r.Interface)
	nw := d.networks[r.NetworkID]

	if nw == nil {
		return nil, fmt.Errorf("Can not find network [ %s ].", r.NetworkID)
	}

	/* if r.Interface.Address != "" {
		return nil, fmt.Errorf("IP address cannot be defined.")
	} */

	nw.endpoint.srcName = nw.hostnic.Name
	nw.endpoint.id = r.EndpointID

	endpointInterface := &network.EndpointInterface{}
	endpointInterface.Address = nw.hostnic.Address
	endpointInterface.MacAddress = nw.hostnic.HardwareAddr

	resp := &network.CreateEndpointResponse{Interface: endpointInterface}
	log.Debug("CreateEndpoint resp interface: [ %+v ] ", resp.Interface)
	return resp, nil
}

func (d *HostNicDriver) EndpointInfo(r *network.InfoRequest) (*network.InfoResponse, error) {
	log.Debug("EndpointInfo Called: [ %+v ]", r)
	d.lock.RLock()
	defer d.lock.RUnlock()
	nw := d.networks[r.NetworkID]
	if nw == nil {
		return nil, fmt.Errorf("Can not find network [ %s ].", r.NetworkID)
	}

	endpoint := nw.endpoint

	value := make(map[string]string)
	value["id"] = endpoint.id
	value["srcName"] = endpoint.srcName
	value["hostNic.Name"] = nw.hostnic.Name
	value["hostNic.Addr"] = nw.hostnic.Address
	value["hostNic.HardwareAddr"] = nw.hostnic.HardwareAddr
	resp := &network.InfoResponse{
		Value: value,
	}
	log.Debug("EndpointInfo resp.Value : [ %+v ]", resp.Value)
	return resp, nil
}
func (d *HostNicDriver) Join(r *network.JoinRequest) (*network.JoinResponse, error) {
	d.lock.Lock()
	defer d.lock.Unlock()
	log.Debug("Join Called: [ %+v ]", r)

	nw := d.networks[r.NetworkID]
	if nw == nil {
		return nil, fmt.Errorf("Can not find network [ %s ].", r.NetworkID)
	}

	endpoint := nw.endpoint
	if endpoint.id != r.EndpointID {
		return nil, fmt.Errorf("Cannot find endpoint by id: %s", r.EndpointID)
	}

	if endpoint.sandboxKey != "" {
		return nil, fmt.Errorf("Endpoint [%s] has bean bind to sandbox [%s]", r.EndpointID, endpoint.sandboxKey)
	}
	gw, _, err := net.ParseCIDR(nw.IPv4Data.Gateway)
	if err != nil {
		return nil, fmt.Errorf("Parse gateway [%s] error: %s", nw.IPv4Data.Gateway, err.Error())
	}
	endpoint.sandboxKey = r.SandboxKey
	resp := network.JoinResponse{
		InterfaceName:         network.InterfaceName{SrcName: endpoint.srcName, DstPrefix: containerVethPrefix},
		DisableGatewayService: false,
		Gateway:               gw.String(),
	}

	log.Debug("Join resp : [ %+v ]", resp)
	return &resp, nil
}
func (d *HostNicDriver) Leave(r *network.LeaveRequest) error {
	log.Debug("Leave Called: [ %+v ]", r)
	d.lock.Lock()
	defer d.lock.Unlock()

	nw := d.networks[r.NetworkID]
	if nw == nil {
		return fmt.Errorf("Can not find network [ %s ].", r.NetworkID)
	}

	endpoint := nw.endpoint
	if endpoint.id == r.EndpointID {
		return fmt.Errorf("Cannot find endpoint by id: %s", r.EndpointID)
	}

	endpoint.sandboxKey = ""
	return nil
}

func (d *HostNicDriver) DeleteEndpoint(r *network.DeleteEndpointRequest) error {
	log.Debug("DeleteEndpoint Called: [ %+v ]", r)
	d.lock.Lock()
	defer d.lock.Unlock()
	nw := d.networks[r.NetworkID]
	if nw == nil {
		return fmt.Errorf("Can not find network [ %s ].", r.NetworkID)
	}

	endpoint := nw.endpoint
	if endpoint.id == r.EndpointID {
		return fmt.Errorf("Cannot find endpoint by id: %s", r.EndpointID)
	}

	link := d.findLinkByName(nw.hostnic.Name)
	if link == nil {
		return nil
	}

	hwaddr, _ := net.ParseMAC(nw.hostnic.HardwareAddr)
	netlink.LinkSetHardwareAddr(link, hwaddr)
	return nil
}

func (d *HostNicDriver) findLinkByName(name string) netlink.Link {
	links, err := netlink.LinkList()
	if err == nil {
		for _, link := range links {
			if link.Attrs().Name == name {
				return link
			}
		}
	}
	return nil
}

func (d *HostNicDriver) DiscoverNew(r *network.DiscoveryNotification) error {
	log.Debug("DiscoverNew Called: [ %+v ]", r)
	return nil
}
func (d *HostNicDriver) DiscoverDelete(r *network.DiscoveryNotification) error {
	log.Debug("DiscoverDelete Called: [ %+v ]", r)
	return nil
}
func (d *HostNicDriver) ProgramExternalConnectivity(r *network.ProgramExternalConnectivityRequest) error {
	log.Debug("ProgramExternalConnectivity Called: [ %+v ]", r)
	return nil
}
func (d *HostNicDriver) RevokeExternalConnectivity(r *network.RevokeExternalConnectivityRequest) error {
	log.Debug("RevokeExternalConnectivity Called: [ %+v ]", r)
	return nil
}

func (d *HostNicDriver) getNetworkByGateway(gateway string) *Network {
	for _, nw := range d.networks {
		if nw.IPv4Data.Gateway == gateway {
			return nw
		}
	}
	return nil
}

func (d *HostNicDriver) findNicFromInterfaces(hardwareAddr string) *HostNic {
	nics, err := net.Interfaces()
	if err == nil {
		for _, nic := range nics {
			if nic.HardwareAddr.String() == hardwareAddr {
				return &HostNic{Name: nic.Name, HardwareAddr: nic.HardwareAddr.String(), Address: GetInterfaceIPAddr(nic)}
			}
		}
	} else {
		log.Error("Get Interfaces error:%s", err.Error())
	}
	return nil
}

func (d *HostNicDriver) findNicFromLinks(hardwareAddr string) *HostNic {
	links, err := netlink.LinkList()
	if err == nil {
		for _, link := range links {
			attr := link.Attrs()
			if attr.HardwareAddr.String() == hardwareAddr {
				return &HostNic{Name: attr.Name, HardwareAddr: attr.HardwareAddr.String()}
			}
		}
	} else {
		log.Error("Get LinkList error:%s", err.Error())
	}
	return nil
}

func (d *HostNicDriver) FindNicByHardwareAddr(hardwareAddr string) *HostNic {
	for _, nw := range d.networks {
		if nw.hostnic.HardwareAddr == hardwareAddr {
			return &nw.hostnic
		}
	}
	nic := d.findNicFromInterfaces(hardwareAddr)
	if nic == nil {
		nic = d.findNicFromLinks(hardwareAddr)
	}
	return nic
}

// ensureNic ensure nic exist and info is update
func (d *HostNicDriver) ensureNic(nic *HostNic) bool {
	existNic := d.findNicFromInterfaces(nic.HardwareAddr)
	if existNic == nil {
		existNic = d.findNicFromLinks(nic.HardwareAddr)
	}
	if existNic != nil {
		// nic dev name may be changed by os, so ensure it is update.
		nic.Name = existNic.Name
	}
	return existNic != nil
}

/* func (d *HostNicDriver) loadConfig() error {
	configFile := fmt.Sprintf("%s/%s", configDir, "config.json")
	exists, err := FileExists(configFile)
	if err != nil {
		return err
	}
	if exists {
		configData, err := ioutil.ReadFile(configFile)
		if err != nil {
			return err
		}
		networks := Networks{}
		err = json.Unmarshal(configData, &networks)
		if err != nil {
			return err
		}
		log.Info("Load config from [%s]", configFile)
		for _, nw := range networks {
			d.RegisterNetwork(nw.ID, nw.IPv4Data)
		}
	}
	return nil
} */

//write driver network to file, wait docker 1.3 to support plugin data persistence.
/* func (d *HostNicDriver) saveConfig() error {
	configFile := fmt.Sprintf("%s/%s", configDir, "config.json")
	data, err := json.Marshal(d.networks)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(configFile, data, os.FileMode(0644))
	if err != nil {
		return err
	}
	log.Debug("Save config [%+v] to [%s]", d.networks, configFile)
	return nil
} */
