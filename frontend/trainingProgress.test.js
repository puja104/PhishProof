const assert = require("assert");
const { getNextDifficultyFromProgress, noScenariosUi } = require("./trainingProgress");

// Returning users who already passed easy must start at medium, not default easy.
assert.strictEqual(
    getNextDifficultyFromProgress({ easy: true, medium: false, hard: false }),
    "medium"
);
assert.strictEqual(
    getNextDifficultyFromProgress({ easy: false, medium: false, hard: false }),
    "easy"
);
assert.strictEqual(
    getNextDifficultyFromProgress({ easy: true, medium: true, hard: true }),
    "done"
);

// Running out of emails at one difficulty is not the same as mastering the category.
const exhausted = noScenariosUi({ easy: true, medium: false, hard: false });
assert.strictEqual(exhausted.mastered, false);
assert.strictEqual(exhausted.title, "No more emails at this level");
assert.ok(!exhausted.message.toLowerCase().includes("mastered"));

const done = noScenariosUi({ easy: true, medium: true, hard: true });
assert.strictEqual(done.mastered, true);
assert.strictEqual(done.title, "Category Complete!");

console.log("trainingProgress tests passed");
