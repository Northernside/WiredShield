let reqs = 0;

const url = "https://dawg.pics/";
const fetchData = async () => {
    console.log(`Request #${reqs}`);
    try {
        const response = await fetch(url);
    } catch (error) {
        console.error("Error fetching data:", error);
    }
};

for (let i = 0; i < 256 ** 2; i++) {
    for (let j = 0; j < 1; j++) {
        fetchData();
        reqs++;
    }
}