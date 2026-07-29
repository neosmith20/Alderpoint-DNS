(function () {
  const canvas = document.getElementById('queryChart');
  if (!canvas) return;
  const data = JSON.parse(canvas.dataset.series || '[]');
  const ctx = canvas.getContext('2d');
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth || 600;
  const height = canvas.clientHeight || 260;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, width, height);
  ctx.font = '12px system-ui, sans-serif';
  ctx.strokeStyle = '#d9dde3';
  ctx.lineWidth = 1;
  for (let i = 0; i < 5; i += 1) {
    const y = 20 + ((height - 45) * i / 4);
    ctx.beginPath();
    ctx.moveTo(36, y);
    ctx.lineTo(width - 12, y);
    ctx.stroke();
  }
  const max = Math.max(1, ...data.map((d) => Math.max(d.total, d.blocked)));
  function line(key, color) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    data.forEach((point, index) => {
      const x = 36 + ((width - 52) * index / Math.max(1, data.length - 1));
      const y = height - 25 - ((height - 55) * point[key] / max);
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }
  line('total', '#155e75');
  line('blocked', '#9f1239');
  ctx.fillStyle = '#18202a';
  ctx.fillText('Total DNS queries', 42, 18);
  ctx.fillStyle = '#9f1239';
  ctx.fillText('Blocked DNS queries', 180, 18);
}());
