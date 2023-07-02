function updateDates() {
    let elementsToDatify = document.getElementsByClassName("datify");
    elementsToDatify = Array.prototype.map.call(elementsToDatify, a => a);
    elementsToDatify.forEach(a => {
        a.innerText = new Date(a.innerHTML).toLocaleDateString() + " " + new Date(a.innerHTML).toTimeString().split(" ")[0];
        a.classList.remove("datify");
    });
}

updateDates();