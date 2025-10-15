const rand = Math.random();
const num = Number.parseFloat(rand).toFixed(3);
if (num > 0.5) {
  console.log(`YAYY ${num} is greater than 0.5 !!!`);
} else {
  console.log(`nay ${num} is smaller than 0.5`);
}

