// flow_counter.go
package main

import (
    "encoding/binary"
    "fmt"
    "net"
)

// Função auxiliar para "retirar" bytes do pacote
func popBytes(packet *[]byte, numBytes int) []byte {
    if len(*packet) < numBytes {
        return nil // Retorna nil se o pacote for menor que o número de bytes desejado
    }
    value := (*packet)[:numBytes]
    *packet = (*packet)[numBytes:]
    return value
}

func popDataPacket(packet *[]byte, lenght int) [] byte {
    bytes := popBytes(packet, lenght)
    if bytes == nil {
        return nil
    }
    return bytes
}

// Funções para ler tipos específicos de dados
func popUint32(packet *[]byte) uint32 {
    bytes := popBytes(packet, 4)
    if bytes == nil {
        return 0
    }
    return binary.BigEndian.Uint32(bytes)
}

func popUint64(packet *[]byte) uint64 {
    bytes := popBytes(packet, 8)
    if bytes == nil {
        return 0
    }
    return binary.BigEndian.Uint64(bytes)
}

type genericHeaderS struct {
    datagramVersion uint32
    ipVersion uint32
    agentIP net.IP
    subAgentID uint32
    sequenceNumber uint32
    sysUptime uint32
    numSamples uint32
}

func genericHeader(packet *[]byte) genericHeaderS {

    // Cria uma instância da estrutura genericHeader
    var header genericHeaderS

    // Extrair os campos do cabeçalho de acordo com a estrutura fornecida
    header.datagramVersion = popUint32(packet)
    header.ipVersion = popUint32(packet)

    // Obter o agente IP como um uint32 e converter para net.IP
    agentIPBytes := make([]byte, 4) // Criar um slice de 4 bytes
    binary.BigEndian.PutUint32(agentIPBytes, popUint32(packet)) // Colocar o uint32 no slice de bytes
    header.agentIP = net.IP(agentIPBytes)

    header.subAgentID = popUint32(packet)
    header.sequenceNumber = popUint32(packet)
    header.sysUptime = popUint32(packet)
    header.numSamples = popUint32(packet)

    if enableLogging {
	    // Imprimir todos os valores dos campos
	    fmt.Printf("################################\n")
	    fmt.Printf("Versão do Datagram: %d\n", header.datagramVersion)
	    fmt.Printf("Versão do IP: %d\n", header.ipVersion)
	    fmt.Printf("Endereço IP do Agente: %s\n", header.agentIP)
	    fmt.Printf("ID do Sub-Agente: %d\n", header.subAgentID)
	    fmt.Printf("Número de Sequência: %d\n", header.sequenceNumber)
	    fmt.Printf("SysUptime (secs): %d\n", header.sysUptime/1000)
	    fmt.Printf("Número de Amostras: %d\n", header.numSamples)
    } 

    // Retorna a estrutura genericHeader
    return header
} 

// Função para verificar o tipo de flow, e retonar um inteiro correspondente ao tipo de flow
func checkFlowType(packet *[]byte) int{
    // Verificar o tipo de flow
    flowType := popUint32(packet)
    if enableLogging {
    fmt.Printf("Tipo de flow: %d\n", flowType)
    } 

    return int(flowType)
}


// Defina a função flowCounter
func flowInterval(packet *[]byte) {

    // Expanded counters sample
    sample_length := popUint32(packet)
    sequence_number := popUint32(packet)
    source_id_type := popUint32(packet)
    source_id_index := popUint32(packet)
    counters_records := popUint32(packet)

    // Generic Interface Counters
    flow_type := popUint32(packet)
    flow_data_length := popUint32(packet)
    if_id := popUint32(packet)
    if_type := popUint32(packet)
    if_speed := popUint64(packet)
    if_direction := popUint32(packet)
    if_status := popUint32(packet)

    // Interface Counters
    if_in_octets := popUint64(packet)
    if_in_pkt := popUint32(packet)
    if_in_multicast := popUint32(packet)
    if_in_broadcast := popUint32(packet)
    if_in_discards := popUint32(packet)
    if_in_errors := popUint32(packet)
    if_in_unknown := popUint32(packet)

    if_out_octets := popUint64(packet)
    if_out_pkt := popUint32(packet)
    if_out_multicast := popUint32(packet)
    if_out_broadcast := popUint32(packet)
    if_out_discards := popUint32(packet)
    if_out_errors := popUint32(packet)

    // Interface mode
    if_promiscuous := popUint32(packet)

    // Ethernet Counters
    eth_flow_type := popUint32(packet)
    eth_flow_data_length := popUint32(packet)
    align := popUint32(packet)
    fcs := popUint32(packet)
    single_collision := popUint32(packet)
    multiple_collision := popUint32(packet)
    sqe_test_errors := popUint32(packet)
    deferred_transmissions := popUint32(packet)
    late_collisions := popUint32(packet)
    excessive_collisions := popUint32(packet)
    internal_mac_transmit_errors := popUint32(packet)
    carrier_sense_errors := popUint32(packet)
    frame_too_longs := popUint32(packet)
    internal_mac_receive_errors := popUint32(packet)
    symbol_errors := popUint32(packet)

    // Verificar se os contadores de entrada e saída são diferentes de zero
    if if_in_octets != 0 || if_out_octets != 0 {

        if enableLogging {
		// imprimir os valores genéricos: 
        fmt.Println("================================")
		fmt.Printf("Comprimento da captura: %d\n", sample_length)
		fmt.Printf("Sequence Number: %d\n", sequence_number)
		fmt.Printf("Source ID Type: %d\n", source_id_type)
		fmt.Printf("Source ID Index: %d\n", source_id_index)
		fmt.Printf("Counters Recorded: %d\n", counters_records)

		fmt.Printf("Tipo de flow: %d\n", flow_type)
		fmt.Printf("Comprimento da captura: %d\n", flow_data_length)
		fmt.Printf("ID da Interface: %d\n", if_id)
		fmt.Printf("Tipo de Interface: %d\n", if_type)
		fmt.Printf("Velocidade da Interface: %d\n", if_speed)
		fmt.Printf("Direção da Interface: %d\n", if_direction)
		fmt.Printf("Status da Interface: %d\n", if_status)
		fmt.Printf("ifPromiscuous: %d\n", if_promiscuous)


        // Imprimir contadores de interface
        fmt.Println("================================")
        fmt.Println("Contadores de Interface:")
        fmt.Printf("ifInOctets: %d\n", if_in_octets)
        fmt.Printf("ifInPackets: %d\n", if_in_pkt)
        fmt.Printf("ifInMulticast: %d\n", if_in_multicast)
        fmt.Printf("ifInBroadcast: %d\n", if_in_broadcast)
        fmt.Printf("ifInDiscards: %d\n", if_in_discards)
        fmt.Printf("ifInErrors: %d\n", if_in_errors)
        fmt.Printf("ifInUnknown: %d\n", if_in_unknown)
        fmt.Printf("ifOutOctets: %d\n", if_out_octets)
        fmt.Printf("ifOutPackets: %d\n", if_out_pkt)
        fmt.Printf("ifOutMulticast: %d\n", if_out_multicast)
        fmt.Printf("ifOutBroadcast: %d\n", if_out_broadcast)
        fmt.Printf("ifOutDiscards: %d\n", if_out_discards)
        fmt.Printf("ifOutErrors: %d\n", if_out_errors)

        // Imprimir contadores Ethernet
        fmt.Println("================================")
        fmt.Println("Contadores Ethernet:")
        fmt.Printf("ethFlowType: %d\n", eth_flow_type)
        fmt.Printf("ethFlowDataLength: %d\n", eth_flow_data_length)
        fmt.Printf("Align: %d\n", align)
        fmt.Printf("FCS: %d\n", fcs)
        fmt.Printf("Single Collisions: %d\n", single_collision)
        fmt.Printf("Multiple Collisions: %d\n", multiple_collision)
        fmt.Printf("SQE Test Errors: %d\n", sqe_test_errors)
        fmt.Printf("Deferred Transmissions: %d\n", deferred_transmissions)
        fmt.Printf("Late Collisions: %d\n", late_collisions)
        fmt.Printf("Excessive Collisions: %d\n", excessive_collisions)
        fmt.Printf("Internal MAC Transmit Errors: %d\n", internal_mac_transmit_errors)
        fmt.Printf("Carrier Sense Errors: %d\n", carrier_sense_errors)
        fmt.Printf("Frame Too Longs: %d\n", frame_too_longs)
        fmt.Printf("Internal MAC Receive Errors: %d\n", internal_mac_receive_errors)
        fmt.Printf("Symbol Errors: %d\n", symbol_errors)
        } 
    }
}


// Defina a função flowCounter
func flowSample(packet *[]byte, maxHeader int) {

    // Expanded counters sample
    sample_length := popUint32(packet)
    sequence_number := popUint32(packet)
    source_id_type := popUint32(packet)
    source_id_index := popUint32(packet)
    sampling_rate := popUint32(packet)
    sample_pool := popUint32(packet)
    drops := popUint32(packet)
    input_if_format := popUint32(packet)
    input_if_value := popUint32(packet)
    output_if_format := popUint32(packet)
    output_if_value := popUint32(packet)
    num_records := popUint32(packet)

    // Raw packet header

    flow_type := popUint32(packet)
    flow_data_length := popUint32(packet)
    header_protocol := popUint32(packet)
    frame_length := popUint32(packet)
    payload_stripped := popUint32(packet)
    sampled_header_size := popUint32(packet)

    // Get the raw sampled packet data
    fmt.Printf("Tamanho do pacote (com payload): %d\n", len(*packet))

    raw_packet_data := popDataPacket(packet, int(sampled_header_size))

    // print the lenght of the packet
    fmt.Printf("Tamanho do pacote (sem payload): %d\n", len(*packet))

    // check if packet still has data
    if len(*packet) > 0 {

        // Extended Switch Data
        ext_flow_type := popUint32(packet) 

        // check if extended flow type is 1001
        if ext_flow_type == 1001 {
        ext_flow_data_length := popUint32(packet)
        src_vlan := popUint32(packet)
        src_priority := popUint32(packet)
        dst_vlan := popUint32(packet)
        dst_priority := popUint32(packet)
        
        fmt.Println("================================")
        fmt.Println("Dados Estendidos do Switch:")
        fmt.Printf("Tipo de Flow Estendido: %d\n", ext_flow_type)
        fmt.Printf("Comprimento da captura: %d\n", ext_flow_data_length)
        fmt.Printf("VLAN de Origem: %d\n", src_vlan)
        fmt.Printf("Prioridade de Origem: %d\n", src_priority)
        fmt.Printf("VLAN de Destino: %d\n", dst_vlan)
        fmt.Printf("Prioridade de Destino: %d\n", dst_priority)
        
        } 
    }

    // imprimir os valores genéricos:

    fmt.Println("================================")
    fmt.Printf("Comprimento da captura: %d\n", sample_length)
    fmt.Printf("Sequence Number: %d\n", sequence_number)
    fmt.Printf("Source ID Type: %d\n", source_id_type)
    fmt.Printf("Source ID Index: %d\n", source_id_index)
    fmt.Printf("Taxa de Amostragem: %d\n", sampling_rate)
    fmt.Printf("Pool de Amostras: %d\n", sample_pool)
    fmt.Printf("Drops: %d\n", drops)
    fmt.Printf("Formato da Interface de Entrada: %d\n", input_if_format)
    fmt.Printf("Valor da Interface de Entrada: %d\n", input_if_value)
    fmt.Printf("Formato da Interface de Saída: %d\n", output_if_format)
    fmt.Printf("Valor da Interface de Saída: %d\n", output_if_value)
    fmt.Printf("Número de Registros: %d\n", num_records)

    // Imprimir contadores de flow
    fmt.Println("================================")
    fmt.Println("Contadores de Flow:")
    fmt.Printf("Tipo de Flow: %d\n", flow_type)
    fmt.Printf("Comprimento da captura: %d\n", flow_data_length)
    fmt.Printf("Protocolo do Cabeçalho: %d\n", header_protocol)
    fmt.Printf("Tamanho do Frame: %d\n", frame_length)
    fmt.Printf("Payload Stripped: %d\n", payload_stripped)
    fmt.Printf("Tamanho do Cabeçalho Amostrado: %d\n", sampled_header_size)

    // Imprimir dados brutos do pacote amostrado
    fmt.Println("================================")
    fmt.Println("Dados do Pacote Amostrado:")
    fmt.Printf("%x\n", raw_packet_data)
}