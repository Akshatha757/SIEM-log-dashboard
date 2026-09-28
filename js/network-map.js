/* ==========================================================================
   SIEM LOG DASHBOARD - Fictional Attack Network Topology Map
   ========================================================================== */

const NETWORK_MAP = {
  containerId: 'networkMapContainer',

  nodes: [
    { id: 'internal', label: 'Internal Subnet', type: 'internal', ip: '192.168.1.0/24', icon: '💻', status: 'Protected', x: 15, y: 50 },
    { id: 'firewall', label: 'NextGen Firewall', type: 'firewall', ip: '10.0.0.1', icon: '🛡️', status: 'Filtering', x: 40, y: 50 },
    { id: 'servers', label: 'Prod DB & Web', type: 'servers', ip: '10.0.2.0/24', icon: '🖥️', status: 'Under Attack', x: 65, y: 50 },
    { id: 'attacker', label: 'Suspicious IP', type: 'attacker', ip: '45.142.214.10', icon: '⚠️', status: 'Blocked', x: 90, y: 50 }
  ],

  render() {
    const container = document.getElementById(this.containerId);
    if (!container) return;

    container.innerHTML = `
      <svg class="network-svg-layer" width="100%" height="100%">
        <defs>
          <linearGradient id="lineGradNormal" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.8"/>
            <stop offset="100%" stop-color="#06b6d4" stop-opacity="0.8"/>
          </linearGradient>
          <linearGradient id="lineGradAttack" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#f97316" stop-opacity="0.9"/>
            <stop offset="100%" stop-color="#ef4444" stop-opacity="0.9"/>
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>

        <!-- Dynamic Connection Lines -->
        <path d="M 120 140 Q 220 100 320 140" fill="none" stroke="url(#lineGradNormal)" stroke-width="3" filter="url(#glow)" class="packet-line" />
        <path d="M 320 140 Q 450 180 580 140" fill="none" stroke="url(#lineGradAttack)" stroke-width="3" filter="url(#glow)" class="packet-line" />
        <path d="M 580 140 Q 700 100 820 140" fill="none" stroke="url(#lineGradAttack)" stroke-width="3" filter="url(#glow)" class="packet-line" />
      </svg>

      <div class="network-nodes-layer">
        ${this.nodes.map(n => `
          <div class="network-node" data-node-id="${n.id}" onclick="NETWORK_MAP.showNodeDetails('${n.id}')">
            <div class="node-icon-wrapper ${n.type}">
              <span>${n.icon}</span>
            </div>
            <div class="node-name">${n.label}</div>
            <div class="node-status">${n.ip} • <span style="color:${n.type === 'attacker' ? 'var(--severity-critical)' : 'var(--cyan-highlight)'}">${n.status}</span></div>
          </div>
        `).join('')}
      </div>
    `;
  },

  showNodeDetails(nodeId) {
    const node = this.nodes.find(n => n.id === nodeId);
    if (!node) return;

    if (window.SIEM_APP) {
      window.SIEM_APP.showToast(`Node ${node.label} (${node.ip}): Status - ${node.status}`, 'INFO');
    }
  }
};
