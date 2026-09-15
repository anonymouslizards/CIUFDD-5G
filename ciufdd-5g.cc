/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2019 Centre Tecnologic de Telecomunicacions de Catalunya (CTTC)
//
// SPDX-License-Identifier: GPL-2.0-only

// Modified from the original 5G-LENA cttc-nr-demo.cc example
// for the CIUFDD-5G dataset.

#include "ns3/antenna-module.h"
#include "ns3/applications-module.h"
#include "ns3/buildings-module.h"
#include "ns3/config-store-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/nr-module.h"
#include "ns3/point-to-point-module.h"

#include <filesystem>
#include <vector>
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Iufd5g");

int
main(int argc, char* argv[])
{
    uint16_t numLegit = 10;

    bool dmgnbat = false;

    bool csgnbat = false;


    int attackers = -1;


    bool logging = false;

    uint32_t packetSizeAttack = 1400;

    const uint32_t legitProfilePacketSize[3] = {512, 20, 256};
    const double legitProfileIntervalMs[3] = {33.032, 2.0, 200.0};

    double totalAttackRatePps = 66666.0;

    Time legitStartTime = Seconds(1.0);
    Time attackStartTime = Seconds(100.0);
    Time simTime = Seconds(150.0);

    uint16_t numerologyBwp1 = 1;
    double centralFrequencyBand1 = 3.5e9;
    double bandwidthBand1 = 20e6;
    double totalTxPower = 35;

    double gnbHeight = 10.0;
    double ueHeight = 1.5;
    double ueMinRadius = 50.0;
    double ueMaxRadius = 200.0;

    std::string outputDir = "./txt";

    CommandLine cmd(__FILE__);
    cmd.AddValue("numLegit", "Number of legitimate IoT devices", numLegit);
    cmd.AddValue("dmgnbat",
                 "Distributed Multi-gNB Attack Topology: spread attackers in "
                 "consecutive blocks across all 5 gNBs. Mutually exclusive with "
                 "--csgnbat; exactly one of the two is required.",
                 dmgnbat);
    cmd.AddValue("csgnbat",
                 "Concentrated Single-gNB Attack Topology: send all attackers to "
                 "one targeted gNB, reproducing single-cell saturation. Mutually "
                 "exclusive with --dmgnbat; exactly one of the two is required.",
                 csgnbat);
    cmd.AddValue("logging", "Enable logging", logging);
    cmd.AddValue("attackers",
                 "Number of attacking devices for this run. If not given, runs "
                 "the full 2-10 sweep (ascending). If given, must be between 2 "
                 "and 10 inclusive -- values outside that range are rejected -- "
                 "and only that single count is run. Works with either "
                 "--dmgnbat or --csgnbat.",
                 attackers);
    cmd.AddValue("packetSizeAttack", "Packet size (bytes) of attack traffic", packetSizeAttack);
    cmd.AddValue("totalAttackRatePps",
                 "Aggregate attack rate in packets/second across all attacking hosts "
                 "(default 66666 pps)",
                 totalAttackRatePps);
    cmd.AddValue("simTime", "Total simulation time", simTime);
    cmd.AddValue("centralFrequencyBand1", "Central frequency (Hz)", centralFrequencyBand1);
    cmd.AddValue("bandwidthBand1", "Bandwidth (Hz)", bandwidthBand1);
    cmd.AddValue("numerologyBwp1", "Numerology index (sets subcarrier spacing)", numerologyBwp1);
    cmd.AddValue("outputDir", "Output directory for results", outputDir);
    cmd.Parse(argc, argv);

    if (dmgnbat == csgnbat)
    {
        std::cerr << "ERROR: you must choose exactly one topology mode.\n"
                  << "  --dmgnbat  Distributed Multi-gNB Attack Topology (attackers spread across 5 gNBs)\n"
                  << "  --csgnbat  Concentrated Single-gNB Attack Topology (attackers on one targeted gNB)\n"
                  << (dmgnbat ? "Both flags were set; pass only one.\n"
                              : "Neither flag was set; pass one of them.\n")
                  << "Example: ./ns3 run \"ciufdd-5g --dmgnbat\"\n";
        return 1;
    }

    if (attackers != -1 && (attackers < 2 || attackers > 10))
    {
        std::cerr << "ERROR: --attackers must be between 2 and 10 inclusive (got " << attackers
                  << "). Values outside this range are not supported.\n"
                  << "Omit --attackers entirely to run the full 2-10 sweep instead.\n"
                  << "Example: ./ns3 run \"ciufdd-5g --dmgnbat --attackers=5\"\n";
        return 1;
    }

    NS_ABORT_IF(centralFrequencyBand1 < 0.5e9 || centralFrequencyBand1 > 100e9);

    if (logging)
    {
        LogComponentEnable("UdpClient", LOG_LEVEL_INFO);
        LogComponentEnable("UdpServer", LOG_LEVEL_INFO);
        LogComponentEnable("LtePdcp", LOG_LEVEL_INFO);
    }

    Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue(10 * 1024 * 1024));

    std::string pcapDir = "pcaps";
    if (!std::filesystem::exists(pcapDir))
    {
        std::filesystem::create_directories(pcapDir);
    }
    if (!std::filesystem::exists(outputDir))
    {
        std::filesystem::create_directories(outputDir);
    }


    const std::vector<uint16_t> attackerCounts =
        (attackers == -1)
            ? std::vector<uint16_t>{2, 3, 4, 5, 6, 7, 8, 9, 10}
            : std::vector<uint16_t>{static_cast<uint16_t>(attackers)};

    const uint16_t numGnb = 5;
    NS_ABORT_IF(numLegit % numGnb != 0);
    const uint16_t numLegitPerGnb = numLegit / numGnb;
    NS_ABORT_IF(numLegitPerGnb > 2);


    std::vector<Vector> gnbCenters;
    for (uint16_t g = 0; g < numGnb; ++g)
    {
        gnbCenters.push_back(Vector(g * 1000.0, 0.0, gnbHeight));
    }


    const double legitRadius = ueMinRadius + 0.25 * (ueMaxRadius - ueMinRadius);
    const double attackerRadius = ueMinRadius + 0.75 * (ueMaxRadius - ueMinRadius);

    std::vector<Vector> legitPositions;
    for (uint16_t g = 0; g < numGnb; ++g)
    {
        for (uint16_t k = 0; k < numLegitPerGnb; ++k)
        {
            double theta = (k == 0) ? 0.0 : M_PI;
            double x = gnbCenters[g].x + legitRadius * std::cos(theta);
            double y = gnbCenters[g].y + legitRadius * std::sin(theta);
            legitPositions.push_back(Vector(x, y, ueHeight));
        }
    }

    for (uint16_t numAttackers : attackerCounts)
    {
        std::cout << "-" << numAttackers << "-" << std::endl;

        std::string simTag = "udp-n" + std::to_string(numAttackers) + "-" +
                              (csgnbat ? "csgnbat" : "dmgnbat") + "-run" +
                              std::to_string(RngSeedManager::GetRun());

        NodeContainer gnbNodes;
        gnbNodes.Create(numGnb);

        NodeContainer legitContainer;
        legitContainer.Create(numLegit);

        NodeContainer attackerContainer;
        attackerContainer.Create(numAttackers);

        NodeContainer ueNodes = NodeContainer(legitContainer, attackerContainer);

        MobilityHelper gnbMobility;
        Ptr<ListPositionAllocator> gnbPosition = CreateObject<ListPositionAllocator>();
        for (uint16_t g = 0; g < numGnb; ++g)
        {
            gnbPosition->Add(gnbCenters[g]);
        }
        gnbMobility.SetPositionAllocator(gnbPosition);
        gnbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        gnbMobility.Install(gnbNodes);


        Ptr<ListPositionAllocator> uePosition = CreateObject<ListPositionAllocator>();
        for (uint16_t i = 0; i < numLegit; ++i)
        {
            uePosition->Add(legitPositions[i]);
        }

        if (csgnbat)
        {

            for (uint16_t i = 0; i < numAttackers; ++i)
            {
                double theta = i * (2.0 * M_PI / numAttackers);
                double x = gnbCenters[0].x + attackerRadius * std::cos(theta);
                double y = gnbCenters[0].y + attackerRadius * std::sin(theta);
                uePosition->Add(Vector(x, y, ueHeight));
            }
        }
        else
        {

            uint16_t attackerPerGnbCapacity = (numAttackers + numGnb - 1) / numGnb;
            NS_ABORT_IF(attackerPerGnbCapacity > 2);

            for (uint16_t i = 0; i < numAttackers; ++i)
            {
                uint16_t assignedGnb = i / attackerPerGnbCapacity;
                uint16_t withinGnbIndex = i % attackerPerGnbCapacity;
                double theta = (withinGnbIndex == 0) ? (M_PI / 2.0) : (3.0 * M_PI / 2.0);
                double x = gnbCenters[assignedGnb].x + attackerRadius * std::cos(theta);
                double y = gnbCenters[assignedGnb].y + attackerRadius * std::sin(theta);
                uePosition->Add(Vector(x, y, ueHeight));
            }
        }

        MobilityHelper ueMobility;
        ueMobility.SetPositionAllocator(uePosition);
        ueMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        ueMobility.Install(ueNodes);

        NS_LOG_INFO("Creating " << ueNodes.GetN() << " IoT UEs (" << numLegit << " legitimate, "
                                 << numAttackers << " attackers) and " << gnbNodes.GetN() << " gNBs");

        Ptr<NrPointToPointEpcHelper> epcHelper = CreateObject<NrPointToPointEpcHelper>();
        Ptr<IdealBeamformingHelper> idealBeamformingHelper = CreateObject<IdealBeamformingHelper>();
        Ptr<NrHelper> nrHelper = CreateObject<NrHelper>();

        nrHelper->SetBeamformingHelper(idealBeamformingHelper);
        nrHelper->SetEpcHelper(epcHelper);

        BandwidthPartInfoPtrVector allBwps;
        CcBwpCreator ccBwpCreator;
        const uint8_t numCcPerBand = 1;

        CcBwpCreator::SimpleOperationBandConf bandConf1(centralFrequencyBand1,
                                                         bandwidthBand1,
                                                         numCcPerBand,
                                                         BandwidthPartInfo::UMi_StreetCanyon);
        OperationBandInfo band1 = ccBwpCreator.CreateOperationBandContiguousCc(bandConf1);

        Config::SetDefault("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue(MilliSeconds(0)));
        nrHelper->SetChannelConditionModelAttribute("UpdatePeriod", TimeValue(MilliSeconds(0)));
        nrHelper->SetPathlossAttribute("ShadowingEnabled", BooleanValue(false));

        nrHelper->InitializeOperationBand(&band1);

        double x = pow(10, totalTxPower / 10);
        double totalBandwidth = bandwidthBand1;
        allBwps = CcBwpCreator::GetAllBwps({band1});

        Packet::EnableChecking();
        Packet::EnablePrinting();

        idealBeamformingHelper->SetAttribute("BeamformingMethod",
                                              TypeIdValue(DirectPathBeamforming::GetTypeId()));
        epcHelper->SetAttribute("S1uLinkDelay", TimeValue(MilliSeconds(0)));

        nrHelper->SetUeAntennaAttribute("NumRows", UintegerValue(1));
        nrHelper->SetUeAntennaAttribute("NumColumns", UintegerValue(1));
        nrHelper->SetUeAntennaAttribute("AntennaElement",
                                         PointerValue(CreateObject<IsotropicAntennaModel>()));

        nrHelper->SetGnbAntennaAttribute("NumRows", UintegerValue(4));
        nrHelper->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
        nrHelper->SetGnbAntennaAttribute("AntennaElement",
                                          PointerValue(CreateObject<IsotropicAntennaModel>()));

        nrHelper->SetGnbBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(0));
        nrHelper->SetUeBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(0));

        NetDeviceContainer gnbNetDev = nrHelper->InstallGnbDevice(gnbNodes, allBwps);
        NetDeviceContainer legitNetDev = nrHelper->InstallUeDevice(legitContainer, allBwps);
        NetDeviceContainer attackerNetDev = nrHelper->InstallUeDevice(attackerContainer, allBwps);

        int64_t randomStream = 1;
        randomStream += nrHelper->AssignStreams(gnbNetDev, randomStream);
        randomStream += nrHelper->AssignStreams(legitNetDev, randomStream);
        randomStream += nrHelper->AssignStreams(attackerNetDev, randomStream);

        for (uint32_t g = 0; g < gnbNetDev.GetN(); ++g)
        {
            nrHelper->GetGnbPhy(gnbNetDev.Get(g), 0)
                ->SetAttribute("Numerology", UintegerValue(numerologyBwp1));
            nrHelper->GetGnbPhy(gnbNetDev.Get(g), 0)
                ->SetAttribute("TxPower",
                                DoubleValue(10 * log10((bandwidthBand1 / totalBandwidth) * x)));
        }

        for (auto it = gnbNetDev.Begin(); it != gnbNetDev.End(); ++it)
        {
            DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
        }
        for (auto it = legitNetDev.Begin(); it != legitNetDev.End(); ++it)
        {
            DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();
        }
        for (auto it = attackerNetDev.Begin(); it != attackerNetDev.End(); ++it)
        {
            DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();
        }

        Ptr<Node> pgw = epcHelper->GetPgwNode();
        NodeContainer remoteHostContainer;
        remoteHostContainer.Create(1);
        Ptr<Node> remoteHost = remoteHostContainer.Get(0);
        InternetStackHelper internet;
        internet.Install(remoteHostContainer);

        PointToPointHelper p2ph;
        p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
        p2ph.SetDeviceAttribute("Mtu", UintegerValue(2500));
        p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.000)));
        NetDeviceContainer internetDevices = p2ph.Install(pgw, remoteHost);

        Ipv4AddressHelper ipv4h;
        Ipv4StaticRoutingHelper ipv4RoutingHelper;
        ipv4h.SetBase("1.0.0.0", "255.0.0.0");
        Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign(internetDevices);
        Ptr<Ipv4StaticRouting> remoteHostStaticRouting =
            ipv4RoutingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>());
        remoteHostStaticRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

        internet.Install(ueNodes);

        Ipv4InterfaceContainer legitIpIface =
            epcHelper->AssignUeIpv4Address(NetDeviceContainer(legitNetDev));
        Ipv4InterfaceContainer attackerIpIface =
            epcHelper->AssignUeIpv4Address(NetDeviceContainer(attackerNetDev));

        for (uint32_t j = 0; j < ueNodes.GetN(); ++j)
        {
            Ptr<Ipv4StaticRouting> ueStaticRouting =
                ipv4RoutingHelper.GetStaticRouting(ueNodes.Get(j)->GetObject<Ipv4>());
            ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
        }

        nrHelper->AttachToClosestEnb(legitNetDev, gnbNetDev);
        nrHelper->AttachToClosestEnb(attackerNetDev, gnbNetDev);

        uint16_t ulPortLegit = 5000;
        uint16_t ulPortAttack = 5001;

        ApplicationContainer serverApps;
        UdpServerHelper ulServerLegit(ulPortLegit);
        UdpServerHelper ulServerAttack(ulPortAttack);
        serverApps.Add(ulServerLegit.Install(remoteHost));
        serverApps.Add(ulServerAttack.Install(remoteHost));

        Address remoteHostAddress = internetIpIfaces.GetAddress(1);



        EpsBearer legitBearer(EpsBearer::NGBR_LOW_LAT_EMBB);
        Ptr<EpcTft> legitTft = Create<EpcTft>();
        EpcTft::PacketFilter ulpfLegit;
        ulpfLegit.remotePortStart = ulPortLegit;
        ulpfLegit.remotePortEnd = ulPortLegit;
        legitTft->Add(ulpfLegit);

        double lambdaAttack = totalAttackRatePps / numAttackers;

        UdpClientHelper ulClientAttack;
        ulClientAttack.SetAttribute("RemotePort", UintegerValue(ulPortAttack));
        ulClientAttack.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
        ulClientAttack.SetAttribute("PacketSize", UintegerValue(packetSizeAttack));
        ulClientAttack.SetAttribute("Interval", TimeValue(Seconds(1.0 / lambdaAttack)));
        ulClientAttack.SetAttribute("RemoteAddress", AddressValue(remoteHostAddress));

        EpsBearer attackBearer(EpsBearer::NGBR_LOW_LAT_EMBB);
        Ptr<EpcTft> attackTft = Create<EpcTft>();
        EpcTft::PacketFilter ulpfAttack;
        ulpfAttack.remotePortStart = ulPortAttack;
        ulpfAttack.remotePortEnd = ulPortAttack;
        attackTft->Add(ulpfAttack);

        ApplicationContainer clientApps;

        for (uint32_t i = 0; i < legitContainer.GetN(); ++i)
        {
            Ptr<Node> ue = legitContainer.Get(i);
            Ptr<NetDevice> ueDevice = legitNetDev.Get(i);

            uint32_t profile = i % 3;
            UdpClientHelper ulClientLegit;
            ulClientLegit.SetAttribute("RemotePort", UintegerValue(ulPortLegit));
            ulClientLegit.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
            ulClientLegit.SetAttribute("PacketSize", UintegerValue(legitProfilePacketSize[profile]));
            ulClientLegit.SetAttribute("Interval",
                                        TimeValue(MilliSeconds(legitProfileIntervalMs[profile])));
            ulClientLegit.SetAttribute("RemoteAddress", AddressValue(remoteHostAddress));

            ApplicationContainer app = ulClientLegit.Install(ue);
            app.Start(legitStartTime);
            app.Stop(simTime);
            clientApps.Add(app);

            nrHelper->ActivateDedicatedEpsBearer(ueDevice, legitBearer, legitTft);
        }

        for (uint32_t i = 0; i < attackerContainer.GetN(); ++i)
        {
            Ptr<Node> ue = attackerContainer.Get(i);
            Ptr<NetDevice> ueDevice = attackerNetDev.Get(i);

            ApplicationContainer app = ulClientAttack.Install(ue);
            app.Start(attackStartTime);
            app.Stop(simTime);
            clientApps.Add(app);

            nrHelper->ActivateDedicatedEpsBearer(ueDevice, attackBearer, attackTft);
        }

        serverApps.Start(Seconds(0.0));
        serverApps.Stop(simTime);

        p2ph.EnablePcap(pcapDir + "/" + simTag, internetDevices.Get(1), true);

        FlowMonitorHelper flowmonHelper;
        NodeContainer endpointNodes;
        endpointNodes.Add(remoteHost);
        endpointNodes.Add(ueNodes);

        Ptr<ns3::FlowMonitor> monitor = flowmonHelper.Install(endpointNodes);
        monitor->SetAttribute("DelayBinWidth", DoubleValue(0.001));
        monitor->SetAttribute("JitterBinWidth", DoubleValue(0.001));
        monitor->SetAttribute("PacketSizeBinWidth", DoubleValue(20));

        Simulator::Stop(simTime);
        Simulator::Run();

        monitor->CheckForLostPackets();
        Ptr<Ipv4FlowClassifier> classifier =
            DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
        FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

        std::ofstream outFile;
        std::string filename = outputDir + "/" + simTag;
        outFile.open(filename.c_str(), std::ofstream::out | std::ofstream::trunc);
        if (!outFile.is_open())
        {
            std::cerr << "Could not open file " << filename << std::endl;
            return 1;
        }
        outFile.setf(std::ios_base::fixed);

        for (auto i = stats.begin(); i != stats.end(); ++i)
        {
            Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
            std::string label = (t.destinationPort == ulPortAttack) ? "attack" : "normal";

            double flowDuration = (t.destinationPort == ulPortAttack)
                                       ? (simTime - attackStartTime).GetSeconds()
                                       : (simTime - legitStartTime).GetSeconds();

            outFile << "Flow " << i->first << " (" << t.sourceAddress << ":" << t.sourcePort << " -> "
                    << t.destinationAddress << ":" << t.destinationPort << ") label=" << label << "\n";
            outFile << "  Tx Packets: " << i->second.txPackets << "\n";
            outFile << "  Tx Bytes:   " << i->second.txBytes << "\n";
            outFile << "  TxOffered:  " << i->second.txBytes * 8.0 / flowDuration / 1e6 << " Mbps\n";
            outFile << "  Rx Bytes:   " << i->second.rxBytes << "\n";
            if (i->second.rxPackets > 0)
            {
                outFile << "  Throughput: " << i->second.rxBytes * 8.0 / flowDuration / 1e6 << " Mbps\n";
                outFile << "  Mean delay: "
                        << 1000 * i->second.delaySum.GetSeconds() / i->second.rxPackets << " ms\n";
                outFile << "  Mean jitter: "
                        << 1000 * i->second.jitterSum.GetSeconds() / i->second.rxPackets << " ms\n";
            }
            else
            {
                outFile << "  Throughput: 0 Mbps\n  Mean delay: 0 ms\n  Mean jitter: 0 ms\n";
            }
            outFile << "  Rx Packets: " << i->second.rxPackets << "\n";
        }
        outFile.close();

        std::ifstream f(filename.c_str());
        if (f.is_open())
        {
            std::cout << f.rdbuf();
        }

        Simulator::Destroy();
    }

    return 0;
}
