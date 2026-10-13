// Display names for upstream transport protocols (provider.Protocol values).
const protocolLabels: Record<string, string> = {
    "kuaifan-wifiin": "WIFIIN",
    "kuaifan-speedin": "SPEEDIN",
    "quickfox-native": "QF Native",
    "transocks-ss": "Shadowsocks",
    "transocks-trojan": "Trojan",
    "baidu-http": "HTTP CONNECT",
};

export function protocolLabel(protocol: string): string {
    return protocolLabels[protocol] ?? protocol;
}
