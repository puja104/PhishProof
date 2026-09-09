// Shared training-progress helpers (used by the simulation page and node tests).
function getNextDifficultyFromProgress(passed) {
    if (!passed.easy) return "easy";
    if (!passed.medium) return "medium";
    if (!passed.hard) return "hard";
    return "done";
}

function noScenariosUi(passed) {
    const mastered = !!(passed.easy && passed.medium && passed.hard);
    if (mastered) {
        return {
            mastered: true,
            title: "Category Complete!",
            message: "You have mastered this category."
        };
    }
    return {
        mastered: false,
        title: "No more emails at this level",
        message: "There are no remaining emails for this difficulty. You have not finished every level yet."
    };
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = { getNextDifficultyFromProgress, noScenariosUi };
}
