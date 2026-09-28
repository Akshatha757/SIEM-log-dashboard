/* ==========================================================================
   SIEM LOG DASHBOARD - Custom Canvas & Radar Visualizations
   ========================================================================= */

const SIEM_CHARTS = {
  activityChart: null,
  radarChart: null,
  activeTimeframe: '24H',

  // Mock time-series data for timeframes
  chartData: {
    '1H': {
      labels: ['09:00', '09:10', '09:20', '09:30', '09:40', '09:50'],
      events: [120, 145, 190, 310, 480, 240],
      alerts: [2, 1, 4, 8, 14, 5],
      threats: [0, 0, 1, 3, 6, 2]
    },
    '6H': {
      labels: ['04:00', '05:00', '06:00', '07:00', '08:00', '09:00'],
      events: [850, 920, 1100, 1400, 2100, 1650],
      alerts: [12, 10, 15, 22, 34, 24],
      threats: [3, 2, 4, 7, 12, 8]
    },
    '24H': {
      labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'],
      events: [3200, 2800, 4500, 6200, 5800, 4900, 4100],
      alerts: [18, 14, 28, 42, 35, 29, 24],
      threats: [4, 3, 9, 14, 11, 8, 7]
    },
    '7D': {
      labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
      events: [28000, 32000, 41000, 39000, 48000, 22000, 19000],
      alerts: [140, 165, 210, 195, 240, 110, 95],
      threats: [32, 41, 58, 45, 62, 28, 22]
    }
  },

  // Initialize Canvas Security Activity Chart
  initActivityChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // Adjust canvas resolution for crisp retina display
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    this.renderActivityChart(canvas, ctx, this.chartData[this.activeTimeframe]);

    // Handle Window Resize
    window.addEventListener('resize', () => {
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.scale(dpr, dpr);
      this.renderActivityChart(canvas, ctx, this.chartData[this.activeTimeframe]);
    });
  },

  setTimeframe(tf, canvasId = 'activityChartCanvas') {
    this.activeTimeframe = tf;
    const canvas = document.getElementById(canvasId);
    if (canvas) {
      const ctx = canvas.getContext('2d');
      this.renderActivityChart(canvas, ctx, this.chartData[tf]);
    }
  },

  renderActivityChart(canvas, ctx, data) {
    const width = canvas.width / (window.devicePixelRatio || 1);
    const height = canvas.height / (window.devicePixelRatio || 1);
    const padding = { top: 30, right: 30, bottom: 40, left: 55 };

    ctx.clearRect(0, 0, width, height);

    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    // Find Max Value for scaling
    const maxVal = Math.max(...data.events) * 1.15;

    // Draw Gridlines & Y-Axis Labels
    const gridLines = 4;
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    ctx.fillStyle = '#64748b';
    ctx.font = '11px Outfit, sans-serif';

    for (let i = 0; i <= gridLines; i++) {
      const y = padding.top + (chartH / gridLines) * i;
      const val = Math.round(maxVal - (maxVal / gridLines) * i);

      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();

      ctx.fillText(val.toLocaleString(), 10, y + 4);
    }

    // X-Axis Labels
    const stepX = chartW / (data.labels.length - 1);
    data.labels.forEach((lbl, idx) => {
      const x = padding.left + stepX * idx;
      ctx.fillText(lbl, x - 12, height - 12);
    });

    // Helper: Draw Smooth Bezier Curve
    const drawCurve = (series, strokeColor, fillColor) => {
      ctx.beginPath();
      const points = series.map((val, idx) => ({
        x: padding.left + stepX * idx,
        y: padding.top + chartH - (val / maxVal) * chartH
      }));

      ctx.moveTo(points[0].x, points[0].y);

      for (let i = 0; i < points.length - 1; i++) {
        const xc = (points[i].x + points[i + 1].x) / 2;
        const yc = (points[i].y + points[i + 1].y) / 2;
        ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
      }
      ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);

      if (fillColor) {
        ctx.lineTo(points[points.length - 1].x, padding.top + chartH);
        ctx.lineTo(points[0].x, padding.top + chartH);
        ctx.closePath();
        ctx.fillStyle = fillColor;
        ctx.fill();
      }

      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 3;
      ctx.stroke();

      // Draw Data Points
      points.forEach(p => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
        ctx.fillStyle = strokeColor;
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.strokeStyle = '#0b1120';
        ctx.stroke();
      });
    };

    // Fill & Stroke Events Line (Blue Gradient)
    const eventGrad = ctx.createLinearGradient(0, padding.top, 0, height - padding.bottom);
    eventGrad.addColorStop(0, 'rgba(59, 130, 246, 0.25)');
    eventGrad.addColorStop(1, 'rgba(59, 130, 246, 0.0)');
    drawCurve(data.events, '#3b82f6', eventGrad);

    // Stroke Alerts Line (Orange)
    const alertScaled = data.alerts.map(v => v * (maxVal / 50)); // Scale for visual alignment
    drawCurve(alertScaled, '#f97316', null);

    // Stroke Threats Line (Red)
    const threatScaled = data.threats.map(v => v * (maxVal / 25));
    drawCurve(threatScaled, '#ef4444', null);
  },

  // Initialize Radar Visualization
  initRadarChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const render = () => {
      const w = canvas.width / dpr;
      const h = canvas.height / dpr;
      const cx = w / 2;
      const cy = h / 2;
      const radius = Math.min(cx, cy) - 20;

      ctx.clearRect(0, 0, w, h);

      // Concentric circles
      const rings = [0.3, 0.6, 0.85, 1.0];
      rings.forEach(r => {
        ctx.beginPath();
        ctx.arc(cx, cy, radius * r, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      });

      // Axis lines
      for (let i = 0; i < 6; i++) {
        const angle = (Math.PI / 3) * i;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + radius * Math.cos(angle), cy + radius * Math.sin(angle));
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
        ctx.stroke();
      }

      // Radar Threat Polygon (Normal: Green, Suspicious: Yellow, Threat: Red)
      const values = [0.85, 0.45, 0.9, 0.3, 0.75, 0.6];
      ctx.beginPath();
      values.forEach((v, i) => {
        const angle = (Math.PI / 3) * i;
        const x = cx + radius * v * Math.cos(angle);
        const y = cy + radius * v * Math.sin(angle);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.closePath();

      const fillGrad = ctx.createRadialGradient(cx, cy, 10, cx, cy, radius);
      fillGrad.addColorStop(0, 'rgba(6, 182, 212, 0.35)');
      fillGrad.addColorStop(0.6, 'rgba(139, 92, 246, 0.25)');
      fillGrad.addColorStop(1, 'rgba(239, 68, 68, 0.2)');

      ctx.fillStyle = fillGrad;
      ctx.fill();
      ctx.strokeStyle = '#06b6d4';
      ctx.lineWidth = 2;
      ctx.stroke();
    };

    render();
  }
};
