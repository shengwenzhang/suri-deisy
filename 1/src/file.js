var game = ns.game;

// 游戏结束的方法
game.end = function() {
    window.location.href = "../1.html";
};

// 在10秒（10000毫秒）后结束游戏
setTimeout(game.end, 10000);
